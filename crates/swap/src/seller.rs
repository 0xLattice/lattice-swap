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
    /// until it is mined, while it can land. Once signed, the lock is the same transaction
    /// whenever it is submitted, and can land only once.
    LockingNex {
        locked: SellerLocked,
        nex_lock: Option<swap_nexus_tx::Transaction>,
    },
    AwaitRedeemSignature {
        locked: SellerLocked,
        nex_lock: swap_nexus_tx::Transaction,
    },
    /// Holds the redeem; first broadcasts it on a view that is not stale and
    /// shows the redeem window open. Once it is sent, `seen`, saved before it
    /// goes out, or once a view has shown it, in the mempool or a block, `s`
    /// may be public: it is broadcast on every view it is missing from,
    /// window or not, until it is `btc_confirmations` deep or a cancel in a
    /// block spent the lock, and in `Cancelling` again whenever that cancel
    /// leaves its block.
    Redeeming {
        locked: SellerLocked,
        nex_lock: swap_nexus_tx::Transaction,
        #[serde(with = "hex_tx")]
        redeem: Transaction,
        seen: bool,
    },
    /// No longer redeems: cancels, then claims the NEX back if the buyer
    /// refunds, or punishes if it does not. `nex_lock` is the NEX lock, if
    /// one was signed: it may have landed. `redeem` is the redeem, if the
    /// seller held one: once it was sent or a view has shown it, `seen`, `s`
    /// may be public, so it is broadcast while the lock is unspent or a
    /// cancel spending it is only in the mempool, and cancel beside it once
    /// due. A refund gives `b`, and `claim` claims the NEX beside that
    /// redeem until the refund is `btc_confirmations` deep: a shallower
    /// reorg can drop the cancel and let the redeem confirm, and a refund
    /// that never confirms leaves punish. A claim that lands ends the swap
    /// `Refunded` at the next Bitcoin view, unless a punish can still win.
    /// A lock the buyer drained with `s` leaves the BTC: the redeem, or
    /// punish at `t2`. From `t2`, whatever the claim, the seller punishes
    /// while the cancel output is unspent or holds only a refund in the
    /// mempool. A punish `btc_confirmations` deep beside a claim still
    /// pending leaves the claim to finish, in `ClaimingNex`: however it
    /// ends, the swap ends `Punished`.
    Cancelling {
        locked: SellerLocked,
        nex_lock: Option<swap_nexus_tx::Transaction>,
        #[serde(with = "hex_tx::option")]
        redeem: Option<Transaction>,
        seen: bool,
        claim: Claiming,
    },
    ClaimingNex(Claim),
    Done(Outcome),
}

/// The claim of the NEX back, in `Cancelling`.
#[derive(Clone, Serialize, Deserialize)]
pub enum Claiming {
    /// No refund has given `b` yet.
    None,
    Pending(Box<Claim>),
    /// The claim is `nex_confirmations` deep, or nothing was locked and
    /// nothing can be any more: the NEX is the seller's.
    Landed,
    /// The buyer spent the lock with `s`: the NEX is gone.
    Drained,
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
        if terms.check().is_err() {
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

impl Seller {
    /// The terms, until the swap ends.
    pub fn terms(&self) -> Option<&Terms> {
        use Seller::*;
        match self {
            AwaitBuyerHello(start) => Some(&start.terms),
            AwaitLockProposal(setup) | AwaitBuyerSignatures { setup, .. } => Some(&setup.terms),
            AwaitFunding { locked, .. }
            | LockingNex { locked, .. }
            | AwaitRedeemSignature { locked, .. }
            | Redeeming { locked, .. }
            | Cancelling { locked, .. } => Some(&locked.setup.terms),
            ClaimingNex(claim) => Some(&claim.setup.terms),
            Done(_) => None,
        }
    }

    /// The Nexus address the NEX is sold from, until the swap ends. The
    /// driver needs its key while [`Seller::signs_nex`].
    pub fn nex_address(&self) -> Option<&str> {
        use Seller::*;
        match self {
            AwaitBuyerHello(start) => Some(&start.nex_address),
            AwaitLockProposal(setup) | AwaitBuyerSignatures { setup, .. } => {
                Some(&setup.nex_address)
            }
            AwaitFunding { locked, .. }
            | LockingNex { locked, .. }
            | AwaitRedeemSignature { locked, .. }
            | Redeeming { locked, .. }
            | Cancelling { locked, .. } => Some(&locked.setup.nex_address),
            ClaimingNex(claim) => Some(&claim.setup.nex_address),
            Done(_) => None,
        }
    }

    /// Whether the swap may still ask the driver to sign the NEX lock:
    /// only until it is signed.
    pub fn signs_nex(&self) -> bool {
        use Seller::*;
        matches!(
            self,
            AwaitBuyerHello(_)
                | AwaitLockProposal(_)
                | AwaitBuyerSignatures { .. }
                | AwaitFunding { .. }
                | LockingNex { nex_lock: None, .. }
        )
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
                if view.funding.is_none() && view.height >= since.saturating_add(terms.t1.into()) {
                    abort(Refusal::Timeout)
                } else if view.funding.unwrap_or(0) < terms.btc_confirmations {
                    let since = Some(since);
                    (AwaitFunding { locked, since }, vec![])
                } else if terms.redeem_closed(&view) {
                    locked.cancelling(None, None, false, Claiming::None, view)
                } else if view.stale.is_some() {
                    // The window may have closed already: no NEX is locked
                    // on a view that cannot tell.
                    let since = Some(since);
                    (AwaitFunding { locked, since }, vec![])
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
                // Its nonce went to another transaction: no submit can
                // land it, unless a reorg takes that back.
                Some(lock) if lock_passed(&locked.setup.terms, lock.body.nonce, &view) => {
                    let nex_lock = Some(lock);
                    (LockingNex { locked, nex_lock }, vec![])
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
                    locked.cancelling(nex_lock, None, false, Claiming::None, view)
                } else {
                    (LockingNex { locked, nex_lock }, vec![])
                }
            }
            (AwaitRedeemSignature { locked, nex_lock }, Event::Bitcoin(view)) => {
                if locked.gives_up(&view) {
                    locked.cancelling(Some(nex_lock), None, false, Claiming::None, view)
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
                    // Never sent: sent first only while the window is open, on
                    // a view that is not stale. Once sent or seen, it is sent
                    // whatever the window or the view, and against a cancel
                    // still in the mempool, which a bump of it can replace.
                    // It is marked sent in the state saved before it goes
                    // out: from then on `s` may be public.
                    None if seen || view.stale.is_none() && !terms.redeem_closed(&view) => {
                        // Beside it, cancel once due: a redeem in the mempool
                        // refuses it, paying twice its fee, but should the
                        // redeem be refused for another reason, cancel opens
                        // punish against a buyer gone.
                        let mut actions = vec![Action::Broadcast(redeem.clone())];
                        actions.extend(locked.cancel(&view));
                        let state = Redeeming {
                            locked,
                            nex_lock,
                            redeem,
                            seen: true,
                        };
                        (state, actions)
                    }
                    // A stale view may show the window open after it closed:
                    // the redeem waits for a fresh one.
                    None if !terms.redeem_closed(&view) => {
                        let state = Redeeming {
                            locked,
                            nex_lock,
                            redeem,
                            seen,
                        };
                        (state, vec![])
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
                        let redeem = Some(redeem);
                        locked.cancelling(Some(nex_lock), redeem, seen, Claiming::None, view)
                    }
                }
            }
            (
                Cancelling {
                    locked,
                    nex_lock,
                    redeem,
                    seen,
                    claim,
                },
                Event::Bitcoin(view),
            ) => locked.cancelling(nex_lock, redeem, seen, claim, view),
            // The claim goes on beside the redeem. Once it lands the NEX is
            // back: the redeem is fought for no longer, or the seller could
            // end with both. Only a punish from `t2` is, against a refund
            // that missed it. Drained, the buyer has the NEX, and the BTC is
            // fought for.
            (
                Cancelling {
                    locked,
                    nex_lock,
                    redeem,
                    seen,
                    claim: Claiming::Pending(claim),
                },
                event @ Event::Nexus(_),
            ) => {
                let (claim, actions) = match (*claim).step(event) {
                    Claimed::Pending(claim, actions) => {
                        (Claiming::Pending(Box::new(claim)), actions)
                    }
                    // Empty, as landed, is left to the next Bitcoin view: a
                    // punish may still win.
                    Claimed::Done | Claimed::Empty => (Claiming::Landed, vec![]),
                    Claimed::Drained => (Claiming::Drained, vec![]),
                };
                let state = Cancelling {
                    locked,
                    nex_lock,
                    redeem,
                    seen,
                    claim,
                };
                (state, actions)
            }
            (ClaimingNex(claim), event) => {
                let punished = claim.punished;
                match claim.step(event) {
                    Claimed::Pending(claim, actions) => (ClaimingNex(claim), actions),
                    _ if punished => (Done(Outcome::Punished), vec![]),
                    Claimed::Done | Claimed::Empty => (Done(Outcome::Refunded), vec![]),
                    Claimed::Drained => (Done(Outcome::Drained), vec![]),
                }
            }
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
            | Redeeming { locked, .. } => Watch {
                bitcoin: bitcoin(locked),
                nexus: None,
                margin: locked.setup.terms.margin,
            },
            Cancelling { locked, claim, .. } => Watch {
                bitcoin: bitcoin(locked),
                nexus: match claim {
                    Claiming::Pending(claim) => claim.watch().nexus,
                    _ => None,
                },
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

    /// Cancel, once due.
    fn cancel(&self, view: &BitcoinView) -> Option<Action> {
        self.setup
            .terms
            .cancel_due(view)
            .then(|| Action::Broadcast(self.setup.cancel(self.lock, &self.buyer_cancel)))
    }

    /// Punish, signed by us alone: valid once cancel is `t2` deep.
    fn punish(&self) -> Action {
        let swap = self.setup.swap();
        let key = self.setup.secrets.key();
        let signature = swap.sign(self.lock, Spend::Punish, &key);
        let punish = swap
            .finalize(self.lock, Spend::Punish, &signature, None)
            .expect("our own signature");
        Action::Broadcast(punish)
    }

    fn cancelling(
        self,
        nex_lock: Option<swap_nexus_tx::Transaction>,
        redeem: Option<Transaction>,
        mut seen: bool,
        mut claim: Claiming,
        view: BitcoinView,
    ) -> (Seller, Vec<Action>) {
        let setup = &self.setup;
        let terms = &setup.terms;
        let mut actions = vec![];
        // A redeem once sent or seen may have revealed `s`, and the buyer may
        // have taken the NEX with it already: while its cancel is not in a
        // block, the redeem is fought for, even against a refund in the
        // mempool, which only a buyer racing it sends. Once the claim has
        // landed, the NEX is back: the redeem is fought for no longer.
        let held = seen && redeem.is_some() && !matches!(claim, Claiming::Landed);
        let lock_spend = setup.spend(self.lock, &view.lock_spend);
        let cancel_spend = setup.spend(self.lock, &view.cancel_spend);
        let fighting = held && matches!(lock_spend, None | Some((Spend::Cancel, 0)));
        // A refund gives `b`, even with its cancel still in the mempool.
        if let (Claiming::None, Some((Spend::Refund, _))) = (&claim, cancel_spend) {
            let refund = &view.cancel_spend.as_ref().expect("matched").tx;
            if let Some(b) = setup.recover(self.lock, Spend::Refund, &self.refund, refund) {
                let lock = match &nex_lock {
                    Some(lock) => Lock::Signed(lock.body.nonce),
                    None => Lock::Unsigned,
                };
                claim = Claiming::Pending(Box::new(Claim::new(setup.clone(), b, lock)));
            }
        }
        // From `t2` the buyer's refund came too late: while the cancel
        // output is unspent or holds only a refund in the mempool, punish
        // can still win, whatever the claim.
        let late = matches!(lock_spend, Some((Spend::Cancel, depth)) if depth >= u32::from(terms.t2))
            && !matches!(cancel_spend, Some((Spend::Refund, depth)) if depth > 0);
        // With `b`, the NEX is claimed. With no redeem held `s` never left,
        // so no one else can spend the lock: only the claim is left, unless
        // punish can still win. With one, the buyer may drain the lock, and
        // the claim goes on beside the fight for the BTC until the refund
        // is `btc_confirmations` deep.
        let refunded = matches!(
            cancel_spend,
            Some((Spend::Refund, depth)) if depth >= terms.btc_confirmations
        );
        if (!held && !late) || refunded {
            claim = match claim {
                Claiming::None => Claiming::None,
                Claiming::Pending(claim) => return (Seller::ClaimingNex(*claim), vec![]),
                Claiming::Landed => return (Seller::Done(Outcome::Refunded), vec![]),
                Claiming::Drained => return (Seller::Done(Outcome::Drained), vec![]),
            };
        }
        match lock_spend {
            // A bump of it can replace a cancel not yet in a block.
            None | Some((Spend::Cancel, 0)) if fighting => {
                actions.extend(redeem.clone().map(Action::Broadcast));
                // Beside a redeem gone from the view, as in `Redeeming`.
                if lock_spend.is_none() {
                    actions.extend(self.cancel(&view));
                }
            }
            None => actions.extend(self.cancel(&view)),
            // Our redeem, sent before the window closed, won.
            Some((Spend::Redeem, depth)) => {
                if depth >= terms.btc_confirmations {
                    return (Seller::Done(Outcome::Swapped), vec![]);
                }
                seen = true;
            }
            Some((_, cancel_depth)) => match cancel_spend {
                // From `t2`, a refund only in the mempool is contested: the
                // driver bumps punish against it as a package. Never one in
                // a block.
                Some((Spend::Refund, 0)) if cancel_depth >= u32::from(terms.t2) => {
                    actions.push(self.punish());
                }
                // One that does not give `b`: never our punish.
                Some((Spend::Refund, _)) => {}
                // Anything but the refund is our punish: its leaf takes our
                // signature alone, on any transaction. Unconfirmed, it is
                // waited for; another punish would only conflict with it.
                // Deep, it leaves a claim still pending to finish: its secrets
                // and its signed claim are kept until the NEX is back or gone.
                _ if view
                    .cancel_spend
                    .as_ref()
                    .is_some_and(|spent| spent.confirmations >= terms.btc_confirmations) =>
                {
                    if let Claiming::Pending(mut claim) = claim {
                        claim.punished = true;
                        return (Seller::ClaimingNex(*claim), vec![]);
                    }
                    return (Seller::Done(Outcome::Punished), vec![]);
                }
                // Whatever the claim: recovering the BTC must not wait on
                // Nexus.
                None if view.cancel_spend.is_none() && cancel_depth >= u32::from(terms.t2) => {
                    actions.push(self.punish());
                }
                _ => {}
            },
        }
        let locked = self;
        let state = Seller::Cancelling {
            locked,
            nex_lock,
            redeem,
            seen,
            claim,
        };
        (state, actions)
    }
}
