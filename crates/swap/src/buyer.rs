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
        if !terms.check() {
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
                    None,
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
                let actions = vec![
                    Action::Send(Message::BuyerSignatures { cancel: own }),
                    Action::Broadcast(funding.clone()),
                ];
                let locked = BuyerLocked {
                    setup,
                    funding,
                    lock,
                    seller_cancel: cancel,
                    refund,
                };
                (AwaitNexLock { locked, cid: None }, actions)
            }
            (AwaitNexLock { locked, cid: None }, Event::Message(Message::NexLocked { cid })) => {
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
                AwaitSellerHello(_) | AwaitFunded(_) | AwaitSellerSignatures { .. },
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
        )
    }

    fn watch(&self) -> Watch {
        use Buyer::*;
        let bitcoin = |locked: &BuyerLocked| Some((locked.setup.swap(), locked.lock));
        match self {
            AwaitNexLock { locked, cid } => Watch {
                bitcoin: bitcoin(locked),
                nexus: cid
                    .as_ref()
                    .and_then(|cid| locked.setup.watch_nexus(Some(cid))),
            },
            AwaitRedeem { locked, .. } | Cancelling { locked, .. } => Watch {
                bitcoin: bitcoin(locked),
                nexus: None,
            },
            ClaimingNex(claim) => Watch {
                bitcoin: None,
                nexus: claim.setup.watch_nexus(claim.cid.as_ref()),
            },
            AwaitSellerHello(_) | AwaitFunded(_) | AwaitSellerSignatures { .. } | Done(_) => {
                Watch {
                    bitcoin: None,
                    nexus: None,
                }
            }
        }
    }
}

impl Buyer {
    /// The Nexus address the NEX is locked at, once the hellos are
    /// exchanged and until the swap ends.
    pub fn lock_address(&self) -> Option<String> {
        use Buyer::*;
        match self {
            AwaitFunded(setup) | AwaitSellerSignatures { setup, .. } => Some(setup.lock_address()),
            AwaitNexLock { locked, .. }
            | AwaitRedeem { locked, .. }
            | Cancelling { locked, .. } => Some(locked.setup.lock_address()),
            ClaimingNex(claim) => Some(claim.setup.lock_address()),
            AwaitSellerHello(_) | Done(_) => None,
        }
    }
}

impl BuyerLocked {
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
                    return (Buyer::ClaimingNex(Claim::new(self.setup, s, true)), vec![]);
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
            Some((_, cancel_depth)) => match setup.spend(self.lock, &view.cancel_spend) {
                None if cancel_depth >= 1 => {
                    let swap = setup.swap();
                    let seller = setup.decrypt(&self.refund);
                    let own = swap.sign(self.lock, Spend::Refund, &setup.secrets.key());
                    let refund = swap
                        .finalize(self.lock, Spend::Refund, &seller, Some(&own))
                        .expect("the seller's adaptor signature was verified");
                    actions.push(Action::Broadcast(refund));
                }
                Some((Spend::Refund, depth)) if depth >= terms.btc_confirmations => {
                    return (Buyer::Done(Outcome::Refunded), vec![]);
                }
                Some((Spend::Punish, depth)) if depth >= terms.btc_confirmations => {
                    return (Buyer::Done(Outcome::Punished), vec![]);
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
