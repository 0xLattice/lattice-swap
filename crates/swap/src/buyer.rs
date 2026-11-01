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
    Done(Outcome),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BuyerStart {
    terms: Terms,
    secrets: Secrets,
    refund_payout: ScriptBuf,
    nex_address: String,
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
                let mut unsigned = funding.clone();
                for input in &mut unsigned.input {
                    input.witness.clear();
                }
                let proposal = Message::LockProposal {
                    funding: unsigned,
                    lock,
                };
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
            (ClaimingNex(claim), event) => match claim.step(event) {
                Claimed::Pending(claim, actions) => (ClaimingNex(claim), actions),
                Claimed::Done => (Done(Outcome::Swapped), vec![]),
                Claimed::Empty | Claimed::Drained => (Done(Outcome::Drained), vec![]),
            },
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
        )
    }

    fn own_spends(&self) -> &'static [Spend] {
        &[Spend::Refund]
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
            AwaitSellerHello(_)
            | AwaitFunded(_)
            | AwaitSellerSignatures { .. }
            | SendingSignatures(_)
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
            Done(_) => None,
        }
    }

    /// The cancel and the fully signed refund, for a watchtower to
    /// broadcast the refund once cancel confirms if this buyer has gone
    /// offline; only once the buyer has given up on the swap without
    /// signing the redeem. The refund reveals `b`, and a seller that learns
    /// `b` while it can still redeem takes both coins: it locks the NEX,
    /// waits for the redeem signature, sweeps the NEX lock with `s` and `b`,
    /// then redeems. Until the buyer gives up, the seller's redeem stays
    /// possible, or the buyer may yet sign it; so the refund goes to no one
    /// before then.
    pub fn watchtower(&self) -> Option<(Transaction, Transaction)> {
        let Buyer::Cancelling {
            locked,
            redeem: None,
        } = self
        else {
            return None;
        };
        let cancel = locked.setup.cancel(locked.lock, &locked.seller_cancel);
        Some((cancel, locked.refund()))
    }

    /// What a relay's `POST /watch` takes for [`Buyer::watchtower`], on
    /// the Bitcoin `network`: the cancel, the refund, and how deep the
    /// refund must be before the watch is done, at most the 144 a relay
    /// takes.
    pub fn watch_request(&self, network: bitcoin::Network) -> Option<serde_json::Value> {
        let ((cancel, refund), terms) = (self.watchtower()?, self.terms()?);
        Some(serde_json::json!({
            "network": network,
            "cancel": serialize_hex(&cancel),
            "refund": serialize_hex(&refund),
            "depth": terms.btc_confirmations.min(144),
        }))
    }

    /// The signed funding transaction, once the buyer holds it and until the
    /// swap ends.
    pub fn funding(&self) -> Option<&Transaction> {
        use Buyer::*;
        match self {
            AwaitSellerSignatures { funding, .. } => Some(funding),
            SendingSignatures(locked)
            | AwaitNexLock { locked, .. }
            | AwaitRedeem { locked, .. }
            | Cancelling { locked, .. } => Some(&locked.funding),
            AwaitSellerHello(_) | AwaitFunded(_) | ClaimingNex(_) | Done(_) => None,
        }
    }

    /// Whether a lapse of this buyer can cost it, nothing else acting for
    /// it: from the funding's broadcast, as t1 nears with no one to cancel,
    /// until the swap is settled; except once it has given up with the
    /// redeem unsigned and a watchtower holds its refund, `watched`.
    pub fn must_stay_open(&self, watched: bool) -> bool {
        use Buyer::*;
        match self {
            AwaitNexLock { .. } | AwaitRedeem { .. } | ClaimingNex(_) => true,
            Cancelling { .. } => !watched || self.watchtower().is_none(),
            AwaitSellerHello(_)
            | AwaitFunded(_)
            | AwaitSellerSignatures { .. }
            | SendingSignatures(_)
            | Done(_) => false,
        }
    }

    /// Steps on one Bitcoin source's view, for a driver that reads several
    /// and steps the machine on a view only when every source shows it
    /// alike. One source alone may do only what is safe whatever it claims,
    /// so that a source that lies can stall a swap but never turn it
    /// against the buyer, and one down for good still lets an unsigned swap
    /// refund and a signed one claim on a redeem:
    ///
    /// 1. Broadcast the funding again while it is unseen. It is signed, and
    ///    the seller's signatures are made against its txid: a lie that it
    ///    is unseen only sends it again.
    /// 2. Give up, at t1 or on a spend of the lock, and broadcast cancel.
    ///    Cancel before t1 is refused by consensus (its CSV), so a lie only
    ///    sends a transaction that cannot be mined yet. With the redeem
    ///    unsigned the buyer moves to cancelling: it will sign no redeem,
    ///    and a lie ends a swap that could have gone through, and nothing
    ///    more. With the redeem signed the state is kept: cancel goes out,
    ///    but the claim of 4 stays open until every source agrees the swap
    ///    is cancelling.
    /// 3. Broadcast the refund of a swap whose redeem was never signed,
    ///    once cancel is in a block. It reveals `b`, as the watchtower's
    ///    copy does, to a seller that cannot redeem without the buyer's
    ///    signature, so it can take nothing the buyer has not given up;
    ///    early, it is refused.
    /// 4. Claim the NEX on a redeem, from the redeem awaited. A redeem
    ///    proves itself: `s` is taken only if it matches the share the
    ///    seller proved at the start, which no source can forge. Awaiting
    ///    the redeem, the buyer has broadcast neither cancel nor the refund,
    ///    so `b` is the buyer's alone and the NEX cannot have gone back.
    ///
    /// Everything else waits for every source:
    ///
    /// - The refund once the redeem is signed. It waits for cancel
    ///   `btc_confirmations` deep, or a seller that orphans cancel's block
    ///   and redeems learns `b` and takes both coins: a source that lies
    ///   about the depth hands it that.
    /// - The claim once cancelling with the redeem signed. The refund may
    ///   have revealed `b`, with which the seller takes the NEX back; it can
    ///   always build a valid redeem, so a source that shows one would stop
    ///   the refund, and a punish takes the BTC too.
    /// - The end, refunded or punished. Ending on a lie stops the refund
    ///   going out, and a punish may then win.
    /// - Any other state or event.
    ///
    /// These stall while a source is down or disagrees. With the redeem
    /// signed, a refund stalled past the punish lets the seller take the
    /// BTC: the cure is the source back, or another in its place, never a
    /// lie believed.
    pub fn step_one_source(self, view: BitcoinView) -> (Self, Vec<Action>) {
        use Buyer::*;
        match self {
            // 1, 2 and 3: the machine's own step, but for the end.
            AwaitNexLock { .. } | Cancelling { redeem: None, .. } => {
                let kept = self.clone();
                match self.step(Event::Bitcoin(view)) {
                    (Done(_), _) => (kept, vec![]),
                    stepped => stepped,
                }
            }
            // 2 and 4.
            AwaitRedeem { locked, redeem } => {
                match locked.clone().cancelling(Some(redeem.clone()), view) {
                    (claim @ ClaimingNex(_), actions) => (claim, actions),
                    (_, actions) => {
                        let actions = locked.cancel_only(actions);
                        (AwaitRedeem { locked, redeem }, actions)
                    }
                }
            }
            // 2.
            Cancelling {
                locked,
                redeem: Some(redeem),
            } => {
                let (_, actions) = locked.clone().cancelling(Some(redeem.clone()), view);
                let actions = locked.cancel_only(actions);
                let redeem = Some(redeem);
                (Cancelling { locked, redeem }, actions)
            }
            state => (state, vec![]),
        }
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

    /// How deep cancel must be before the refund, which reveals `b`.
    fn refund_depth(&self, redeem: &Option<EncryptedSignature>) -> u32 {
        match redeem {
            Some(_) => self.setup.terms.btc_confirmations,
            None => 1,
        }
    }

    /// Of `actions`, the broadcasts that spend the lock: cancel.
    fn cancel_only(&self, mut actions: Vec<Action>) -> Vec<Action> {
        actions.retain(|action| {
            matches!(action, Action::Broadcast(tx)
                if tx.input.iter().any(|input| input.previous_output == self.lock))
        });
        actions
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
            // public either way.
            Some((Spend::Redeem, _)) => {
                let tx = &view.lock_spend.as_ref().expect("matched").tx;
                let s = redeem
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
            // Refund only once cancel is in a block: a refund spending a
            // cancel that a redeem then displaces would hand the seller `b`.
            // Once the seller holds our redeem signature, a seller that
            // orphans the block could do just that, so cancel must be
            // `btc_confirmations` deep.
            Some((_, cancel_depth)) => match &view.cancel_spend {
                Some(spent) if spent.confirmations >= terms.btc_confirmations => {
                    let outcome = match setup.spend(self.lock, &view.cancel_spend) {
                        Some((Spend::Refund, _)) => Outcome::Refunded,
                        // Anything but our refund is the seller's punish: its
                        // leaf takes the seller's signature alone, on any
                        // transaction.
                        _ => Outcome::Punished,
                    };
                    return (Buyer::Done(outcome), vec![]);
                }
                Some(spent) if spent.confirmations > 0 => {}
                // A spend still in the mempool may yet be replaced by the
                // refund, so the refund goes out until one is in a block.
                _ if cancel_depth >= self.refund_depth(&redeem) => {
                    actions.push(Action::Broadcast(self.refund()));
                }
                _ => {}
            },
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
