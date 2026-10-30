use super::*;

/// The seller's side: has NEX, wants BTC.
#[derive(Clone, Serialize, Deserialize)]
pub enum Seller {
    AwaitBuyerHello(SellerStart),
    AwaitLockProposal(Setup),
    /// Has sent its cancel and refund signatures.
    AwaitBuyerSignatures {
        setup: Setup,
        lock: OutPoint,
        refund: EncryptedSignature,
    },
    /// Waits for the funding transaction to be `btc_confirmations` deep.
    AwaitFunding {
        locked: SellerLocked,
        seen: bool,
    },
    /// Submits the NEX lock until the node takes it.
    LockingNex {
        locked: SellerLocked,
        nonce: Option<u64>,
    },
    AwaitRedeemSignature {
        locked: SellerLocked,
        cid: String,
    },
    /// Has broadcast the redeem; waits for it to confirm.
    Redeeming {
        locked: SellerLocked,
        cid: String,
        #[serde(with = "hex_tx")]
        redeem: Transaction,
    },
    /// No longer redeems: cancels, then claims the NEX back if the buyer
    /// refunds, or punishes if it does not. `cid` is the NEX lock, if the
    /// node took one.
    Cancelling {
        locked: SellerLocked,
        cid: Option<String>,
    },
    ClaimingNex(Claim),
    Done(Outcome),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SellerStart {
    terms: Terms,
    secrets: Secrets,
    nex_key: SecretBytes,
    redeem_payout: ScriptBuf,
    punish_payout: ScriptBuf,
}

/// The BTC lock as agreed, with what the seller needs to act on it.
#[derive(Clone, Serialize, Deserialize)]
pub struct SellerLocked {
    setup: Setup,
    lock: OutPoint,
    /// Our refund adaptor signature: recovers `b` from the refund.
    refund: EncryptedSignature,
    buyer_cancel: Signature,
}

impl Seller {
    /// A swap with fresh secrets. `nex_key` holds the NEX to sell; a
    /// reclaimed lock returns to its address.
    pub fn new(
        terms: Terms,
        nex_key: SecretBytes,
        redeem_payout: ScriptBuf,
        punish_payout: ScriptBuf,
    ) -> Result<Self, Refusal> {
        if !terms.check() {
            return Err(Refusal::Terms);
        }
        Ok(Seller::AwaitBuyerHello(SellerStart {
            terms,
            secrets: Secrets::random(),
            nex_key,
            redeem_payout,
            punish_payout,
        }))
    }
}

fn abort(refusal: Refusal) -> (Seller, Vec<Action>) {
    (Seller::Done(Outcome::Aborted(refusal)), vec![])
}

impl Machine for Seller {
    fn step(self, event: Event) -> (Self, Vec<Action>) {
        use Seller::*;
        match (self, event) {
            (
                AwaitBuyerHello(start),
                Event::Message(Message::BuyerHello {
                    key,
                    share,
                    refund_payout,
                }),
            ) => {
                let payouts = Payouts {
                    redeem: start.redeem_payout,
                    refund: refund_payout,
                    punish: start.punish_payout,
                };
                let nex_address = start.nex_key.nex_address();
                let setup = match Setup::new(
                    start.terms,
                    Side::Seller,
                    start.secrets,
                    key,
                    &share,
                    payouts,
                    nex_address,
                    Some(start.nex_key),
                ) {
                    Ok(setup) => setup,
                    Err(refusal) => return abort(refusal),
                };
                let hello = Message::SellerHello {
                    key: setup.secrets.key().public_key(),
                    share: Box::new(ShareProof::new(&setup.secrets.share())),
                    redeem_payout: setup.redeem_payout.clone(),
                    punish_payout: setup.punish_payout.clone(),
                };
                (AwaitLockProposal(setup), vec![Action::Send(hello)])
            }
            (AwaitLockProposal(setup), Event::Message(Message::LockProposal { funding, lock })) => {
                let swap = setup.swap();
                if lock_output(&swap, &funding) != Some(lock) {
                    return abort(Refusal::Funding);
                }
                let key = setup.secrets.key();
                let cancel = swap.sign(lock, Spend::Cancel, &key);
                let refund = swap
                    .encrypted_sign(lock, Spend::Refund, &key)
                    .expect("refund takes an adaptor signature");
                let message = Message::SellerSignatures {
                    cancel,
                    refund: refund.clone(),
                };
                (
                    AwaitBuyerSignatures {
                        setup,
                        lock,
                        refund,
                    },
                    vec![Action::Send(message)],
                )
            }
            (
                AwaitBuyerSignatures {
                    setup,
                    lock,
                    refund,
                },
                Event::Message(Message::BuyerSignatures { cancel }),
            ) => {
                if !setup
                    .swap()
                    .verify(lock, Spend::Cancel, Party::Buyer, &cancel)
                {
                    return abort(Refusal::Signature);
                }
                let locked = SellerLocked {
                    setup,
                    lock,
                    refund,
                    buyer_cancel: cancel,
                };
                (
                    AwaitFunding {
                        locked,
                        seen: false,
                    },
                    vec![],
                )
            }
            (AwaitFunding { locked, seen }, Event::Bitcoin(view)) => {
                let terms = &locked.setup.terms;
                if view.funding.unwrap_or(0) < terms.btc_confirmations {
                    let seen = seen || view.funding.is_some();
                    (AwaitFunding { locked, seen }, vec![])
                } else if terms.redeem_closed(&view) {
                    Cancelling { locked, cid: None }.step(Event::Bitcoin(view))
                } else {
                    (
                        LockingNex {
                            locked,
                            nonce: None,
                        },
                        vec![],
                    )
                }
            }
            (AwaitFunding { seen: false, .. }, Event::Timeout) => abort(Refusal::Timeout),
            (LockingNex { locked, nonce }, Event::Nexus(view)) => {
                // The nonce is fixed the first time, so the lock submitted
                // again after an error or a restart is the same transaction
                // and can land only once.
                let nonce = nonce.unwrap_or(view.own.nonce);
                let lock = locked.nex_lock(nonce);
                let nonce = Some(nonce);
                (LockingNex { locked, nonce }, vec![Action::Submit(lock)])
            }
            (LockingNex { locked, .. }, Event::Submitted(cid)) => {
                let message = Message::NexLocked { cid: cid.clone() };
                (
                    AwaitRedeemSignature { locked, cid },
                    vec![Action::Send(message)],
                )
            }
            (LockingNex { locked, nonce }, Event::Bitcoin(view)) => {
                if locked.gives_up(&view) {
                    Cancelling { locked, cid: None }.step(Event::Bitcoin(view))
                } else {
                    (LockingNex { locked, nonce }, vec![])
                }
            }
            (AwaitRedeemSignature { locked, cid }, Event::Bitcoin(view)) => {
                if locked.gives_up(&view) {
                    let cid = Some(cid);
                    Cancelling { locked, cid }.step(Event::Bitcoin(view))
                } else {
                    (AwaitRedeemSignature { locked, cid }, vec![])
                }
            }
            // The driver feeds a fresh Bitcoin view before every message, so
            // being here means the redeem window was open a moment ago.
            (
                AwaitRedeemSignature { locked, cid },
                Event::Message(Message::RedeemSignature { redeem }),
            ) => match locked.redeem(&redeem) {
                Some(redeem) => (
                    Redeeming {
                        locked,
                        cid,
                        redeem: redeem.clone(),
                    },
                    vec![Action::Broadcast(redeem)],
                ),
                None => (AwaitRedeemSignature { locked, cid }, vec![]),
            },
            (
                Redeeming {
                    locked,
                    cid,
                    redeem,
                },
                Event::Bitcoin(view),
            ) => {
                let terms = &locked.setup.terms;
                match locked.setup.spend(locked.lock, &view.lock_spend) {
                    Some((Spend::Redeem, depth)) if depth >= terms.btc_confirmations => {
                        (Done(Outcome::Swapped), vec![])
                    }
                    Some((Spend::Redeem, _)) => (
                        Redeeming {
                            locked,
                            cid,
                            redeem,
                        },
                        vec![],
                    ),
                    // Not seen, perhaps never sent: send it again, but only
                    // while the window is open.
                    None if !terms.redeem_closed(&view) => {
                        let actions = vec![Action::Broadcast(redeem.clone())];
                        let state = Redeeming {
                            locked,
                            cid,
                            redeem,
                        };
                        (state, actions)
                    }
                    _ => {
                        let cid = Some(cid);
                        Cancelling { locked, cid }.step(Event::Bitcoin(view))
                    }
                }
            }
            (Cancelling { locked, cid }, Event::Bitcoin(view)) => locked.cancelling(cid, view),
            (ClaimingNex(claim), event) => match claim.step(event) {
                Claimed::Pending(claim, actions) => (ClaimingNex(claim), actions),
                Claimed::Done | Claimed::Empty => (Done(Outcome::Refunded), vec![]),
                Claimed::Drained => (Done(Outcome::Drained), vec![]),
            },
            (
                AwaitBuyerHello(_) | AwaitLockProposal(_) | AwaitBuyerSignatures { .. },
                Event::Timeout,
            ) => abort(Refusal::Timeout),
            (state, _) => (state, vec![]),
        }
    }

    fn outcome(&self) -> Option<Outcome> {
        match self {
            Seller::Done(outcome) => Some(*outcome),
            _ => None,
        }
    }

    fn awaits_message(&self) -> bool {
        matches!(
            self,
            Seller::AwaitBuyerHello(_)
                | Seller::AwaitLockProposal(_)
                | Seller::AwaitBuyerSignatures { .. }
                | Seller::AwaitFunding { seen: false, .. }
        )
    }

    fn watch(&self) -> Watch {
        use Seller::*;
        let bitcoin = |locked: &SellerLocked| Some((locked.setup.swap(), locked.lock));
        match self {
            AwaitFunding { locked, .. }
            | AwaitRedeemSignature { locked, .. }
            | Redeeming { locked, .. }
            | Cancelling { locked, .. } => Watch {
                bitcoin: bitcoin(locked),
                nexus: None,
            },
            LockingNex { locked, .. } => Watch {
                bitcoin: bitcoin(locked),
                nexus: locked.setup.watch_nexus(None),
            },
            ClaimingNex(claim) => Watch {
                bitcoin: None,
                nexus: claim.setup.watch_nexus(claim.cid.as_ref()),
            },
            AwaitBuyerHello(_) | AwaitLockProposal(_) | AwaitBuyerSignatures { .. } | Done(_) => {
                Watch {
                    bitcoin: None,
                    nexus: None,
                }
            }
        }
    }
}

impl SellerLocked {
    /// Too late to redeem, or the buyer already cancelled.
    fn gives_up(&self, view: &BitcoinView) -> bool {
        self.setup.terms.redeem_closed(view) || view.lock_spend.is_some()
    }

    /// The transfer of `nex_amount` to the lock address.
    fn nex_lock(&self, nonce: u64) -> swap_nexus_tx::Transaction {
        let terms = &self.setup.terms;
        let key = self.setup.nex_key.as_ref().expect("the seller's setup");
        let body = TransactionBody::transfer(
            &self.setup.nex_address,
            &self.setup.lock_address(),
            terms.nex_amount,
            terms.nex_fee,
            nonce,
        )
        .expect("the terms were checked");
        let mut transaction = swap_nexus_tx::Transaction::new(body);
        transaction.sign(&key.signing_key());
        transaction
    }

    /// The redeem, if `adaptor` is the buyer's signature on it encrypted to
    /// our share point.
    fn redeem(&self, adaptor: &EncryptedSignature) -> Option<Transaction> {
        let swap = self.setup.swap();
        if !swap.verify_encrypted(self.lock, Spend::Redeem, adaptor) {
            return None;
        }
        let buyer = self.setup.decrypt(adaptor);
        let seller = swap.sign(self.lock, Spend::Redeem, &self.setup.secrets.key());
        swap.finalize(self.lock, Spend::Redeem, &seller, Some(&buyer))
            .ok()
    }

    fn cancelling(self, cid: Option<String>, view: BitcoinView) -> (Seller, Vec<Action>) {
        let setup = &self.setup;
        let terms = &setup.terms;
        let mut actions = vec![];
        match setup.spend(self.lock, &view.lock_spend) {
            None if terms.cancel_due(&view) => {
                actions.push(Action::Broadcast(
                    setup.cancel(self.lock, &self.buyer_cancel),
                ));
            }
            None => {}
            // Our redeem, sent before the window closed, won.
            Some((Spend::Redeem, depth)) => {
                if depth >= terms.btc_confirmations {
                    return (Seller::Done(Outcome::Swapped), vec![]);
                }
            }
            Some((_, cancel_depth)) => match setup.spend(self.lock, &view.cancel_spend) {
                Some((Spend::Refund, _)) => {
                    let refund = &view.cancel_spend.as_ref().expect("matched").tx;
                    if let Some(b) = setup.recover(self.lock, Spend::Refund, &self.refund, refund) {
                        let claim = Claim::new(self.setup, b, cid.is_some());
                        return (Seller::ClaimingNex(claim), vec![]);
                    }
                }
                Some((Spend::Punish, depth)) if depth >= terms.btc_confirmations => {
                    return (Seller::Done(Outcome::Punished), vec![]);
                }
                None if cancel_depth >= u32::from(terms.t2) => {
                    let swap = setup.swap();
                    let key = setup.secrets.key();
                    let signature = swap.sign(self.lock, Spend::Punish, &key);
                    let punish = swap
                        .finalize(self.lock, Spend::Punish, &signature, None)
                        .expect("our own signature");
                    actions.push(Action::Broadcast(punish));
                }
                _ => {}
            },
        }
        (Seller::Cancelling { locked: self, cid }, actions)
    }
}
