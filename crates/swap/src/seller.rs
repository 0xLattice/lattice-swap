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
    /// `since` is the height it started waiting at: if the funding is still
    /// unseen `t1` blocks later, the seller stops.
    AwaitFunding {
        locked: SellerLocked,
        since: Option<u32>,
    },
    /// Signs the NEX lock at the nonce a synced node shows, then submits it
    /// until it is mined. Once signed, the lock is the same transaction
    /// whenever it is submitted, and can land only once.
    LockingNex {
        locked: SellerLocked,
        nex_lock: Option<swap_nexus_tx::Transaction>,
    },
    AwaitRedeemSignature {
        locked: SellerLocked,
        nex_lock: swap_nexus_tx::Transaction,
    },
    /// Holds the redeem; broadcasts it on every view that shows the redeem
    /// window open, until it confirms. Once a view has shown it, in the
    /// mempool or a block, `s` may be public: it is broadcast on every
    /// view it is missing from, window or not, until it is
    /// `btc_confirmations` deep or a cancel in a block spent the lock.
    Redeeming {
        locked: SellerLocked,
        nex_lock: swap_nexus_tx::Transaction,
        #[serde(with = "hex_tx")]
        redeem: Transaction,
        #[serde(default)]
        seen: bool,
    },
    /// No longer redeems: cancels, then claims the NEX back if the buyer
    /// refunds, or punishes if it does not. `nex_lock` is the NEX lock, if
    /// one was signed: it may have landed.
    Cancelling {
        locked: SellerLocked,
        nex_lock: Option<swap_nexus_tx::Transaction>,
    },
    ClaimingNex(Claim),
    Done(Outcome),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SellerStart {
    terms: Terms,
    secrets: Secrets,
    nex_address: String,
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
    /// A swap with fresh secrets. `nex_address` holds the NEX to sell, and
    /// a reclaimed lock returns to it; the driver holds its key.
    pub fn new(
        terms: Terms,
        nex_address: String,
        redeem_payout: ScriptBuf,
        punish_payout: ScriptBuf,
    ) -> Result<Self, Refusal> {
        if !terms.check() {
            return Err(Refusal::Terms);
        }
        Ok(Seller::AwaitBuyerHello(SellerStart {
            terms,
            secrets: Secrets::random(),
            nex_address,
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
                let setup = match Setup::new(
                    start.terms,
                    Side::Seller,
                    start.secrets,
                    key,
                    &share,
                    payouts,
                    start.nex_address,
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
                        since: None,
                    },
                    vec![],
                )
            }
            (AwaitFunding { locked, since }, Event::Bitcoin(view)) => {
                let terms = &locked.setup.terms;
                let since = since.unwrap_or(view.height);
                if view.funding.is_none() && view.height >= since + u32::from(terms.t1) {
                    abort(Refusal::Timeout)
                } else if view.funding.unwrap_or(0) < terms.btc_confirmations {
                    let since = Some(since);
                    (AwaitFunding { locked, since }, vec![])
                } else if terms.redeem_closed(&view) {
                    let nex_lock = None;
                    Cancelling { locked, nex_lock }.step(Event::Bitcoin(view))
                } else {
                    let nex_lock = None;
                    (LockingNex { locked, nex_lock }, vec![])
                }
            }
            (LockingNex { locked, nex_lock }, Event::Nexus(view)) => match nex_lock {
                // Only a synced node knows the next nonce.
                None if !synced(&view.health) => (LockingNex { locked, nex_lock }, vec![]),
                None => {
                    let sign = Action::SignNex(locked.nex_lock(view.own.nonce));
                    (LockingNex { locked, nex_lock }, vec![sign])
                }
                Some(lock)
                    if view
                        .watched
                        .as_ref()
                        .is_some_and(|(_, depth)| depth.is_some()) =>
                {
                    let message = Message::NexLocked { cid: lock.cid() };
                    let state = AwaitRedeemSignature {
                        locked,
                        nex_lock: lock,
                    };
                    (state, vec![Action::Send(message)])
                }
                // The same bytes again: the node answers with their CID
                // while it pools them, and takes them back if it dropped
                // them.
                Some(lock) => {
                    let submit = Action::Submit(lock.clone());
                    let nex_lock = Some(lock);
                    (LockingNex { locked, nex_lock }, vec![submit])
                }
            },
            (
                LockingNex {
                    locked,
                    nex_lock: None,
                },
                Event::NexSigned(lock),
            ) => {
                if lock.body != locked.nex_lock(lock.body.nonce) || !lock.verify() {
                    let nex_lock = None;
                    return (LockingNex { locked, nex_lock }, vec![]);
                }
                // Saved before it is submitted: from here on it may land.
                let submit = Action::Submit(lock.clone());
                let nex_lock = Some(lock);
                (LockingNex { locked, nex_lock }, vec![submit])
            }
            (LockingNex { locked, nex_lock }, Event::Bitcoin(view)) => {
                if locked.gives_up(&view) {
                    Cancelling { locked, nex_lock }.step(Event::Bitcoin(view))
                } else {
                    (LockingNex { locked, nex_lock }, vec![])
                }
            }
            (AwaitRedeemSignature { locked, nex_lock }, Event::Bitcoin(view)) => {
                if locked.gives_up(&view) {
                    let nex_lock = Some(nex_lock);
                    Cancelling { locked, nex_lock }.step(Event::Bitcoin(view))
                } else {
                    (AwaitRedeemSignature { locked, nex_lock }, vec![])
                }
            }
            // Only kept: the redeem goes out on the next Bitcoin view, and
            // only if that view shows the window open. The view this
            // message arrived on may be stale.
            (
                AwaitRedeemSignature { locked, nex_lock },
                Event::Message(Message::RedeemSignature { redeem }),
            ) => match locked.redeem(&redeem) {
                Some(redeem) => (
                    Redeeming {
                        locked,
                        nex_lock,
                        redeem,
                        seen: false,
                    },
                    vec![],
                ),
                None => (AwaitRedeemSignature { locked, nex_lock }, vec![]),
            },
            (
                Redeeming {
                    locked,
                    nex_lock,
                    redeem,
                    seen,
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
                            nex_lock,
                            redeem,
                            seen: true,
                        },
                        vec![],
                    ),
                    // Not seen, perhaps never sent: send it, but only while
                    // the window is open. Seen once, it is sent whatever
                    // the window, and against a cancel still in the mempool,
                    // which a bump of it can replace.
                    None if seen || !terms.redeem_closed(&view) => {
                        let actions = vec![Action::Broadcast(redeem.clone())];
                        let state = Redeeming {
                            locked,
                            nex_lock,
                            redeem,
                            seen,
                        };
                        (state, actions)
                    }
                    Some((Spend::Cancel, 0)) if seen => {
                        let actions = vec![Action::Broadcast(redeem.clone())];
                        let state = Redeeming {
                            locked,
                            nex_lock,
                            redeem,
                            seen,
                        };
                        (state, actions)
                    }
                    _ => {
                        let nex_lock = Some(nex_lock);
                        Cancelling { locked, nex_lock }.step(Event::Bitcoin(view))
                    }
                }
            }
            (Cancelling { locked, nex_lock }, Event::Bitcoin(view)) => {
                locked.cancelling(nex_lock, view)
            }
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
        )
    }

    fn own_spends(&self) -> &'static [Spend] {
        &[Spend::Redeem, Spend::Punish]
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
                margin: locked.setup.terms.margin,
            },
            LockingNex { locked, nex_lock } => Watch {
                bitcoin: bitcoin(locked),
                nexus: locked.setup.watch_nexus(nex_lock.as_ref().map(|t| t.cid())),
                margin: locked.setup.terms.margin,
            },
            ClaimingNex(claim) => claim.watch(),
            AwaitBuyerHello(_) | AwaitLockProposal(_) | AwaitBuyerSignatures { .. } | Done(_) => {
                Watch {
                    bitcoin: None,
                    nexus: None,
                    margin: 0,
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
    fn nex_lock(&self, nonce: u64) -> TransactionBody {
        let terms = &self.setup.terms;
        TransactionBody::transfer(
            &self.setup.nex_address,
            &self.setup.lock_address(),
            terms.nex_amount,
            terms.nex_fee,
            nonce,
        )
        .expect("the terms were checked")
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

    fn cancelling(
        self,
        nex_lock: Option<swap_nexus_tx::Transaction>,
        view: BitcoinView,
    ) -> (Seller, Vec<Action>) {
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
                        let lock = match &nex_lock {
                            Some(lock) => Lock::Signed(lock.body.nonce),
                            None => Lock::Unsigned,
                        };
                        let claim = Claim::new(self.setup, b, lock);
                        return (Seller::ClaimingNex(claim), vec![]);
                    }
                }
                // Anything but the refund is our punish: its leaf takes our
                // signature alone, on any transaction. Unconfirmed, it is
                // waited for; another punish would only conflict with it.
                _ if view
                    .cancel_spend
                    .as_ref()
                    .is_some_and(|spent| spent.confirmations >= terms.btc_confirmations) =>
                {
                    return (Seller::Done(Outcome::Punished), vec![]);
                }
                None if view.cancel_spend.is_none() && cancel_depth >= u32::from(terms.t2) => {
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
        let locked = self;
        (Seller::Cancelling { locked, nex_lock }, actions)
    }
}
