use super::*;

/// The buyer's side: has BTC, wants NEX.
#[derive(Clone, Serialize, Deserialize)]
pub enum Buyer {
    AwaitSellerHello(BuyerStart),
    /// Waits for its own wallet to build and sign the funding transaction.
    AwaitFunded(Setup),
    /// Has proposed the lock; holds the signed funding transaction back
    /// until it holds the seller's signatures.
    AwaitSellerSignatures {
        setup: Setup,
        #[serde(with = "hex_tx")]
        funding: Transaction,
        lock: OutPoint,
    },
    /// Has verified the seller's signatures and is sending its own; once
    /// they are out, broadcasts the funding transaction.
    SendingSignatures(BuyerLocked),
    /// Has broadcast the funding transaction. `cid` is the NEX lock the
    /// seller named.
    AwaitNexLock {
        locked: BuyerLocked,
        cid: Option<String>,
    },
    /// Has sent its redeem adaptor signature.
    AwaitRedeem {
        locked: BuyerLocked,
        redeem: EncryptedSignature,
    },
    /// Cancels and refunds, or claims the NEX if the seller's redeem wins.
    Cancelling {
        locked: BuyerLocked,
        redeem: Option<EncryptedSignature>,
    },
    ClaimingNex(Claim),
    /// The seller's punish is `btc_confirmations` deep: the BTC is its,
    /// and the NEX, if it was locked, waits at the lock address, which only
    /// `s` and `b` together spend. Asks the seller for `s` and claims the
    /// NEX with it, as eigenwallet's CLI asks its ASB to redeem the XMR
    /// cooperatively after a punish. `seen`: the buyer saw the NEX lock
    /// confirmed. `again`: refused as not yet punished, once, and asked
    /// again: the seller's view of the punish may lag ours.
    AskingShare {
        setup: Setup,
        seen: bool,
        #[serde(default)]
        again: bool,
        /// Stopped refunding on a spend of the cancel output that is no
        /// punish it could check: while it asks, it watches the cancel
        /// output, and goes back to refunding should it show none.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unchecked: Option<Box<Unchecked>>,
    },
    /// Punished, and the seller gave no `s` this time: the swap has ended
    /// for this run, but keeps the secrets, so that a resume asks again.
    Punished {
        setup: Setup,
        seen: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unchecked: Option<Box<Unchecked>>,
    },
    Done(Outcome),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BuyerStart {
    terms: Terms,
    secrets: Secrets,
    refund_payout: ScriptBuf,
    nex_address: String,
}

/// The [`Buyer::Cancelling`] that stopped refunding on a spend of the
/// cancel output that is no punish it could check.
#[derive(Clone, Serialize, Deserialize)]
pub struct Unchecked {
    locked: BuyerLocked,
    redeem: Option<EncryptedSignature>,
}

/// The BTC lock as agreed, with what the buyer needs to act on it.
#[derive(Clone, Serialize, Deserialize)]
pub struct BuyerLocked {
    setup: Setup,
    #[serde(with = "hex_tx")]
    funding: Transaction,
    lock: OutPoint,
    seller_cancel: Signature,
    /// The seller's refund adaptor signature, which `b` decrypts.
    refund: EncryptedSignature,
}

impl Buyer {
    /// A swap with fresh secrets, and the hello that opens it. The NEX
    /// arrives at `nex_address`.
    pub fn start(
        terms: Terms,
        refund_payout: ScriptBuf,
        nex_address: String,
    ) -> Result<(Self, Vec<Action>), Refusal> {
        if terms.check().is_err() {
            return Err(Refusal::Terms);
        }
        let secrets = Secrets::random();
        let hello = Message::BuyerHello {
            key: secrets.key().public_key(),
            share: Box::new(ShareProof::new(&secrets.share())),
            refund_payout: refund_payout.clone(),
        };
        let start = BuyerStart {
            terms,
            secrets,
            refund_payout,
            nex_address,
        };
        Ok((Buyer::AwaitSellerHello(start), vec![Action::Send(hello)]))
    }
}

/// The lock proposal: `funding` without its witnesses.
fn proposal(funding: &Transaction, lock: OutPoint) -> Message {
    let mut unsigned = funding.clone();
    for input in &mut unsigned.input {
        input.witness.clear();
    }
    Message::LockProposal {
        funding: unsigned,
        lock,
    }
}

fn abort(refusal: Refusal) -> (Buyer, Vec<Action>) {
    (Buyer::Done(Outcome::Aborted(refusal)), vec![])
}

impl Machine for Buyer {
    fn step(self, event: Event) -> (Self, Vec<Action>) {
        use Buyer::*;
        match (self, event) {
            (
                AwaitSellerHello(start),
                Event::Message(Message::SellerHello {
                    key,
                    share,
                    redeem_payout,
                    punish_payout,
                }),
            ) => {
                let payouts = Payouts {
                    redeem: redeem_payout,
                    refund: start.refund_payout,
                    punish: punish_payout,
                };
                match Setup::new(
                    start.terms,
                    Side::Buyer,
                    start.secrets,
                    key,
                    &share,
                    payouts,
                    start.nex_address,
                ) {
                    Ok(setup) => {
                        let fund = Action::FundLock {
                            script_pubkey: setup.swap().lock_script_pubkey(),
                            amount: setup.terms.btc_amount,
                        };
                        (AwaitFunded(setup), vec![fund])
                    }
                    Err(refusal) => abort(refusal),
                }
            }
            (AwaitFunded(setup), Event::Funded(funding)) => {
                // Signed, every input must be segwit: a witness and no
                // scriptSig, so the txid the seller signs against is the
                // one that confirms.
                let segwit = funding.input.iter().all(|input| !input.witness.is_empty());
                let Some(lock) = lock_output(&setup.swap(), &funding).filter(|_| segwit) else {
                    return abort(Refusal::Funding);
                };
                let proposal = proposal(&funding, lock);
                (
                    AwaitSellerSignatures {
                        setup,
                        funding,
                        lock,
                    },
                    vec![Action::Send(proposal)],
                )
            }
            (
                AwaitSellerSignatures {
                    setup,
                    funding,
                    lock,
                },
                Event::Message(Message::SellerSignatures { cancel, refund }),
            ) => {
                let swap = setup.swap();
                if !swap.verify(lock, Spend::Cancel, Party::Seller, &cancel)
                    || !swap.verify_encrypted(lock, Spend::Refund, &refund)
                {
                    return abort(Refusal::Signature);
                }
                let own = swap.sign(lock, Spend::Cancel, &setup.secrets.key());
                let send = Action::Send(Message::BuyerSignatures { cancel: own });
                let locked = BuyerLocked {
                    setup,
                    funding,
                    lock,
                    seller_cancel: cancel,
                    refund,
                };
                (SendingSignatures(locked), vec![send])
            }
            // A seller without our cancel signature would never lock, so
            // the funding waits for them to be sent.
            (SendingSignatures(locked), Event::Sent) => {
                let broadcast = Action::Broadcast(locked.funding.clone());
                (AwaitNexLock { locked, cid: None }, vec![broadcast])
            }
            // A CID that is not one names nothing a node could show: it is
            // refused here, once, and the buyer waits on, cancelling at t1.
            (AwaitNexLock { locked, cid: None }, Event::Message(Message::NexLocked { cid }))
                if swap_nexus_tx::is_cid(&cid) =>
            {
                let cid = Some(cid);
                (AwaitNexLock { locked, cid }, vec![])
            }
            (
                AwaitNexLock {
                    locked,
                    cid: Some(cid),
                },
                Event::Nexus(view),
            ) => {
                let setup = &locked.setup;
                if !nex_lock_holds(&setup.terms, &setup.lock_address(), &view) {
                    let cid = Some(cid);
                    return (AwaitNexLock { locked, cid }, vec![]);
                }
                let redeem = setup
                    .swap()
                    .encrypted_sign(locked.lock, Spend::Redeem, &setup.secrets.key())
                    .expect("redeem takes an adaptor signature");
                let message = Message::RedeemSignature {
                    redeem: redeem.clone(),
                };
                (AwaitRedeem { locked, redeem }, vec![Action::Send(message)])
            }
            (AwaitNexLock { locked, cid }, Event::Bitcoin(view)) => {
                if locked.gives_up(&view) {
                    return Cancelling {
                        locked,
                        redeem: None,
                    }
                    .step(Event::Bitcoin(view));
                }
                // Broadcast again until a node shows it.
                let actions = match view.funding {
                    None => vec![Action::Broadcast(locked.funding.clone())],
                    Some(_) => vec![],
                };
                (AwaitNexLock { locked, cid }, actions)
            }
            (AwaitRedeem { locked, redeem }, Event::Bitcoin(view)) => {
                if locked.gives_up(&view) {
                    let redeem = Some(redeem);
                    Cancelling { locked, redeem }.step(Event::Bitcoin(view))
                } else {
                    (AwaitRedeem { locked, redeem }, vec![])
                }
            }
            (Cancelling { locked, redeem }, Event::Bitcoin(view)) => {
                locked.cancelling(redeem, view)
            }
            (ClaimingNex(claim), event) => {
                // Claiming with `s` after a punish, the secrets are kept: a
                // lock read empty, never seen, may yet show the NEX to a
                // later resume.
                let punished = claim.punished.then(|| claim.setup.clone());
                match (claim.step(event), punished) {
                    (Claimed::Pending(claim, actions), _) => (ClaimingNex(claim), actions),
                    (Claimed::Done, _) => (Done(Outcome::Swapped), vec![]),
                    (Claimed::Empty, Some(setup)) => {
                        let unchecked = None;
                        let seen = false;
                        (
                            Punished {
                                setup,
                                seen,
                                unchecked,
                            },
                            vec![],
                        )
                    }
                    (Claimed::Drained, Some(_)) => (Done(Outcome::Punished), vec![]),
                    (Claimed::Empty | Claimed::Drained, None) => (Done(Outcome::Drained), vec![]),
                }
            }
            // Only `s` itself: the share the seller proved at the start.
            (
                AskingShare {
                    setup,
                    seen,
                    unchecked,
                    ..
                },
                Event::Message(Message::ShareAnswer(ShareAnswer::Share(share))),
            ) => match KeyShare::from_bytes(share) {
                Some(key)
                    if secp256k1_point(&key) == setup.other_secp256k1
                        && key.public().compress().to_bytes() == setup.other_ed25519 =>
                {
                    let lock = if seen { Lock::Seen } else { Lock::Unsigned };
                    let mut claim = Claim::new(setup, share, lock);
                    claim.punished = true;
                    (ClaimingNex(claim), vec![])
                }
                _ => (
                    Punished {
                        setup,
                        seen,
                        unchecked,
                    },
                    vec![],
                ),
            },
            (
                AskingShare {
                    setup,
                    seen,
                    again: false,
                    unchecked,
                },
                Event::Message(Message::ShareAnswer(ShareAnswer::Refused(
                    ShareRefusal::NotPunished,
                ))),
            ) => {
                let again = true;
                let ask = vec![Action::Send(Message::ShareRequest)];
                let state = AskingShare {
                    setup,
                    seen,
                    again,
                    unchecked,
                };
                (state, ask)
            }
            (
                AskingShare {
                    setup,
                    seen,
                    unchecked,
                    ..
                },
                Event::Message(Message::ShareAnswer(ShareAnswer::Refused(_))) | Event::Timeout,
            ) => (
                Punished {
                    setup,
                    seen,
                    unchecked,
                },
                vec![],
            ),
            // Our refund deep, or the cancel output shown unspent again:
            // the spend we stopped on is gone, and refunding goes on.
            (
                AskingShare {
                    setup,
                    seen,
                    again,
                    unchecked: Some(unchecked),
                },
                Event::Bitcoin(view),
            ) => {
                let Unchecked { locked, redeem } = (*unchecked).clone();
                match locked.cancelling(redeem, view) {
                    (AskingShare { .. }, _) => {
                        let unchecked = Some(unchecked);
                        let state = AskingShare {
                            setup,
                            seen,
                            again,
                            unchecked,
                        };
                        (state, vec![])
                    }
                    next => next,
                }
            }
            (
                AwaitSellerHello(_)
                | AwaitFunded(_)
                | AwaitSellerSignatures { .. }
                | SendingSignatures(_),
                Event::Timeout,
            ) => abort(Refusal::Timeout),
            (state, _) => (state, vec![]),
        }
    }

    fn outcome(&self) -> Option<Outcome> {
        match self {
            Buyer::Done(outcome) => Some(*outcome),
            Buyer::Punished { .. } => Some(Outcome::Punished),
            _ => None,
        }
    }

    fn awaits_message(&self) -> bool {
        matches!(
            self,
            Buyer::AwaitSellerHello(_)
                | Buyer::AwaitFunded(_)
                | Buyer::AwaitSellerSignatures { .. }
                | Buyer::SendingSignatures(_)
                | Buyer::AskingShare { .. }
        )
    }

    fn own_spends(&self) -> &'static [Spend] {
        &[Spend::Refund]
    }

    /// Until the seller can redeem: it may still need the cancel signature,
    /// which it waits for before it locks NEX, or the redeem one. Again
    /// once punished, to ask for `s`.
    fn rejoin(&self) -> Option<Rejoin> {
        use Buyer::*;
        match self {
            AwaitFunded(setup)
            | AwaitSellerSignatures { setup, .. }
            | AskingShare { setup, .. } => Some(setup.rejoin()),
            SendingSignatures(locked)
            | AwaitNexLock { locked, .. }
            | AwaitRedeem { locked, .. } => Some(locked.setup.rejoin()),
            AwaitSellerHello(_)
            | Cancelling { .. }
            | ClaimingNex(_)
            | Punished { .. }
            | Done(_) => None,
        }
    }

    fn resend(&self) -> Option<Message> {
        use Buyer::*;
        match self {
            AwaitSellerSignatures { funding, lock, .. } => Some(proposal(funding, *lock)),
            SendingSignatures(locked) | AwaitNexLock { locked, .. } => {
                let setup = &locked.setup;
                let cancel = setup
                    .swap()
                    .sign(locked.lock, Spend::Cancel, &setup.secrets.key());
                Some(Message::BuyerSignatures { cancel })
            }
            AwaitRedeem { redeem, .. } => Some(Message::RedeemSignature {
                redeem: redeem.clone(),
            }),
            AskingShare { .. } => Some(Message::ShareRequest),
            _ => None,
        }
    }

    fn resumed(self) -> Self {
        match self {
            Buyer::Punished {
                setup,
                seen,
                unchecked,
            } => Buyer::AskingShare {
                setup,
                seen,
                again: false,
                unchecked,
            },
            state => state,
        }
    }

    fn watch(&self) -> Watch {
        use Buyer::*;
        let bitcoin = |locked: &BuyerLocked| Some((locked.setup.swap(), locked.lock));
        match self {
            AwaitNexLock { locked, cid } => Watch {
                bitcoin: bitcoin(locked),
                nexus: cid
                    .as_ref()
                    .and_then(|cid| locked.setup.watch_nexus(Some(cid.clone()))),
                margin: locked.setup.terms.margin,
            },
            AwaitRedeem { locked, .. } | Cancelling { locked, .. } => Watch {
                bitcoin: bitcoin(locked),
                nexus: None,
                margin: locked.setup.terms.margin,
            },
            ClaimingNex(claim) => claim.watch(),
            AskingShare {
                unchecked: Some(unchecked),
                ..
            } => Watch {
                bitcoin: bitcoin(&unchecked.locked),
                nexus: None,
                margin: unchecked.locked.setup.terms.margin,
            },
            AwaitSellerHello(_)
            | AwaitFunded(_)
            | AwaitSellerSignatures { .. }
            | SendingSignatures(_)
            | AskingShare { .. }
            | Punished { .. }
            | Done(_) => Watch {
                bitcoin: None,
                nexus: None,
                margin: 0,
            },
        }
    }
}

impl Buyer {
    /// The terms, until the swap ends.
    pub fn terms(&self) -> Option<&Terms> {
        use Buyer::*;
        match self {
            AwaitSellerHello(start) => Some(&start.terms),
            AwaitFunded(setup) | AwaitSellerSignatures { setup, .. } => Some(&setup.terms),
            SendingSignatures(locked)
            | AwaitNexLock { locked, .. }
            | AwaitRedeem { locked, .. }
            | Cancelling { locked, .. } => Some(&locked.setup.terms),
            ClaimingNex(claim) => Some(&claim.setup.terms),
            AskingShare { setup, .. } | Punished { setup, .. } => Some(&setup.terms),
            Done(_) => None,
        }
    }

    /// Where a refund pays this side, until the swap ends.
    pub fn refund_payout(&self) -> Option<&bitcoin::Script> {
        use Buyer::*;
        match self {
            AwaitSellerHello(start) => Some(&start.refund_payout),
            AwaitFunded(setup) | AwaitSellerSignatures { setup, .. } => Some(&setup.refund_payout),
            SendingSignatures(locked)
            | AwaitNexLock { locked, .. }
            | AwaitRedeem { locked, .. }
            | Cancelling { locked, .. } => Some(&locked.setup.refund_payout),
            ClaimingNex(claim) => Some(&claim.setup.refund_payout),
            AskingShare { setup, .. } | Punished { setup, .. } => Some(&setup.refund_payout),
            Done(_) => None,
        }
    }

    /// Whether the buyer has signed the redeem and the swap is not yet
    /// settled: from then on the seller may redeem at any moment, and the
    /// buyer's refund, if it comes to that, must beat the punish.
    pub fn must_stay_open(&self) -> bool {
        matches!(
            self,
            Buyer::AwaitRedeem { .. }
                | Buyer::Cancelling {
                    redeem: Some(_),
                    ..
                }
        )
    }

    /// The Nexus address the NEX is locked at, once the hellos are
    /// exchanged and until the swap ends.
    pub fn lock_address(&self) -> Option<String> {
        use Buyer::*;
        match self {
            AwaitFunded(setup) | AwaitSellerSignatures { setup, .. } => Some(setup.lock_address()),
            SendingSignatures(locked)
            | AwaitNexLock { locked, .. }
            | AwaitRedeem { locked, .. }
            | Cancelling { locked, .. } => Some(locked.setup.lock_address()),
            ClaimingNex(claim) => Some(claim.setup.lock_address()),
            AskingShare { setup, .. } | Punished { setup, .. } => Some(setup.lock_address()),
            AwaitSellerHello(_) | Done(_) => None,
        }
    }
}

impl BuyerLocked {
    /// The refund, fully signed. It reveals `b`.
    fn refund(&self) -> Transaction {
        let setup = &self.setup;
        let swap = setup.swap();
        let seller = setup.decrypt(&self.refund);
        let own = swap.sign(self.lock, Spend::Refund, &setup.secrets.key());
        swap.finalize(self.lock, Spend::Refund, &seller, Some(&own))
            .expect("the seller's adaptor signature was verified")
    }

    /// The lock was spent, or cancel is due.
    fn gives_up(&self, view: &BitcoinView) -> bool {
        view.lock_spend.is_some() || self.setup.terms.cancel_due(view)
    }

    fn cancelling(
        self,
        redeem: Option<EncryptedSignature>,
        view: BitcoinView,
    ) -> (Buyer, Vec<Action>) {
        let setup = &self.setup;
        let terms = &setup.terms;
        let mut actions = vec![];
        match setup.spend(self.lock, &view.lock_spend) {
            // The seller redeemed, in a block or still in the mempool: `s` is
            // public either way. A copy that never signed the redeem derives
            // the adaptor signature it would have sent: signing is
            // deterministic, and `recover` takes only the proven `s`.
            Some((Spend::Redeem, _)) => {
                let tx = &view.lock_spend.as_ref().expect("matched").tx;
                let adaptor = redeem.clone().or_else(|| {
                    let key = setup.secrets.key();
                    setup.swap().encrypted_sign(self.lock, Spend::Redeem, &key)
                });
                let s = adaptor
                    .as_ref()
                    .and_then(|adaptor| setup.recover(self.lock, Spend::Redeem, adaptor, tx));
                if let Some(s) = s {
                    let claim = Claim::new(self.setup, s, Lock::Seen);
                    return (Buyer::ClaimingNex(claim), vec![]);
                }
            }
            None if terms.cancel_due(&view) => {
                actions.push(Action::Broadcast(
                    setup.cancel(self.lock, &self.seller_cancel),
                ));
            }
            None => {}
            // Refund only once cancel is `btc_confirmations` deep: a refund
            // spending a cancel that a redeem then displaces would hand the
            // seller `b`. A seller holding our redeem signature that orphans
            // the block could do just that, and no copy of this state can
            // tell whether another copy sent it, so the depth holds always.
            Some((_, cancel_depth)) => {
                // The seller's punish: the agreed one, or any transaction it
                // signed through the punish leaf, which takes its signature
                // alone, in a block where its `t2` lets it be. Whatever else
                // a backend names as spending the cancel output is not one.
                let punished = view
                    .cancel_spend
                    .as_ref()
                    .filter(|spent| {
                        spent.confirmations > 0
                            && setup.punish(self.lock, cancel_depth, spent, true)
                    })
                    .map(|spent| spent.confirmations);
                // Deep, any other spend that waited `t2`, as the punish leaf
                // makes it, ends the refund all the same: the seller may
                // spend through that leaf in a shape we cannot check, and
                // our refund would never confirm. It stops no refund that
                // can still win safely: a spend shown before `t2` is
                // refused, and from `t2` the seller's punish may beat the
                // refund anyway. A backend that lies then can as well drop
                // the refund we send through it.
                let gone = view.cancel_spend.as_ref().is_some_and(|spent| {
                    spent.confirmations >= terms.btc_confirmations
                        && setup.after_t2(self.lock, cancel_depth, spent)
                });
                let checked = punished.is_some_and(|depth| depth >= terms.btc_confirmations);
                match (setup.spend(self.lock, &view.cancel_spend), punished) {
                    (Some((Spend::Refund, depth)), _) if depth >= terms.btc_confirmations => {
                        return (Buyer::Done(Outcome::Refunded), vec![]);
                    }
                    (Some((Spend::Refund, depth)), _) if depth > 0 => {}
                    // The BTC is the seller's: `s` can only give us the NEX.
                    _ if checked || gone => {
                        let seen = redeem.is_some();
                        let (setup, unchecked) = if checked {
                            (self.setup, None)
                        } else {
                            let setup = self.setup.clone();
                            let locked = self;
                            (setup, Some(Box::new(Unchecked { locked, redeem })))
                        };
                        let ask = vec![Action::Send(Message::ShareRequest)];
                        let state = Buyer::AskingShare {
                            setup,
                            seen,
                            again: false,
                            unchecked,
                        };
                        return (state, ask);
                    }
                    (_, Some(_)) => {}
                    // A spend still in the mempool may yet be replaced by the
                    // refund, so the refund goes out until one is in a block.
                    _ if cancel_depth >= terms.btc_confirmations => {
                        actions.push(Action::Broadcast(self.refund()));
                    }
                    _ => {}
                }
            }
        }
        (
            Buyer::Cancelling {
                locked: self,
                redeem,
            },
            actions,
        )
    }
}
