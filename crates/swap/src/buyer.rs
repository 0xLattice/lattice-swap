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
