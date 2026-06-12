// This file is part of midnight-ledger.
// Copyright (C) 2025 Midnight Foundation
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use base_crypto::{
    rng::SplittableRng,
    signatures::{Signature, SigningKey},
};
use coin_structure::coin::{NIGHT, UserAddress};
use lazy_static::lazy_static;
use midnight_ledger::{
    dust::{DustActions, DustPublicKey, DustRegistration, INITIAL_DUST_PARAMETERS, InitialNonce},
    semantics::TransactionResult,
    structure::{
        CNightGeneratesDustEvent, Intent, SystemTransaction, Transaction, UnshieldedOffer,
        UtxoOutput, UtxoSpend,
    },
    test_utilities::{Resolver, TestState, test_resolver, tx_prove_bind},
    verify::WellFormedStrictness,
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::collections::VecDeque;
use storage::{arena::Sp, db::InMemoryDB};

lazy_static! {
    static ref RESOLVER: Resolver = test_resolver("");
}

#[tokio::test]
async fn test_registration_dust_payment() {
    let mut rng = StdRng::seed_from_u64(0x42);
    // Initial states
    let mut state: TestState<InMemoryDB> = TestState::new(&mut rng);
    let strictness = WellFormedStrictness::default();
    let verifying_key = state.night_key.verifying_key();
    let addr = UserAddress::from(verifying_key.clone());

    const NIGHT_VAL: u128 = 1_000_000;
    const DUST_VAL: u128 = NIGHT_VAL * INITIAL_DUST_PARAMETERS.night_dust_ratio as u128;

    state.reward_night(&mut rng, NIGHT_VAL).await;
    state.fast_forward(INITIAL_DUST_PARAMETERS.time_to_cap());

    let utxo_ih = state.ledger.utxo.utxos.iter().next().unwrap().0.intent_hash;

    let mut intent = Intent::<(), _, _, _>::empty(&mut rng, state.time);
    intent.guaranteed_unshielded_offer = Some(Sp::new(UnshieldedOffer {
        inputs: vec![UtxoSpend {
            intent_hash: utxo_ih,
            output_no: 0,
            owner: verifying_key,
            type_: NIGHT,
            value: NIGHT_VAL,
        }]
        .into(),
        outputs: vec![UtxoOutput {
            owner: addr,
            type_: NIGHT,
            value: NIGHT_VAL,
        }]
        .into(),
        signatures: vec![].into(),
    }));
    let t0 = state.time;
    intent.dust_actions = Some(Sp::new(DustActions {
        spends: vec![].into(),
        registrations: vec![DustRegistration {
            allow_fee_payment: DUST_VAL,
            dust_address: Some(Sp::new(DustPublicKey::from(state.dust_key.clone()))),
            night_key: state.night_key.verifying_key(),
            signature: None,
        }]
        .into(),
        ctime: state.time,
    }));
    let intent = intent
        .sign(
            &mut rng,
            1,
            &[state.night_key.clone()],
            &[],
            &[state.night_key.clone()],
        )
        .unwrap();
    dbg!(&intent);
    midnight_ledger::init_logger(midnight_ledger::LogLevel::Trace);
    let tx = Transaction::from_intents("local-test", [(1, intent)].into_iter().collect());
    // Erase for fees due to technicality of the runtime fees calculation being slightly inaccurate
    // due to only having the proof-erased tx to hand.
    let dust_fee = dbg!(
        tx.erase_proofs()
            .erase_signatures()
            .fees(&state.ledger.parameters, true)
            .unwrap()
    );
    let result = state.apply(&tx, strictness).unwrap();
    assert!(matches!(result, TransactionResult::Success(_)));
    let dust_bal = state.dust.wallet_balance(state.time);
    let dt = state.time - t0;
    // Add dust generation from time passing
    let dust_generated =
        dt.as_seconds() as u128 * NIGHT_VAL * INITIAL_DUST_PARAMETERS.generation_decay_rate as u128;
    assert!(dust_bal > dust_generated);
    assert!(dbg!(dust_bal) <= dbg!(DUST_VAL - dust_fee + dust_generated));
}

#[tokio::test]
async fn test_cnight_dust_payment() {
    let mut rng = StdRng::seed_from_u64(0x42);
    // Initial states
    let mut state: TestState<InMemoryDB> = TestState::new(&mut rng);
    const CNIGHT_BAL: u128 = 10_000_000;
    let nonce = InitialNonce(rng.r#gen());
    state
        .apply_system_tx(&SystemTransaction::CNightGeneratesDustUpdate {
            events: vec![CNightGeneratesDustEvent {
                action: midnight_ledger::structure::CNightGeneratesDustActionType::Create,
                nonce,
                owner: DustPublicKey::from(state.dust_key.clone()),
                time: state.time,
                value: CNIGHT_BAL,
            }],
        })
        .unwrap();
    state.fast_forward(INITIAL_DUST_PARAMETERS.time_to_cap());
    assert_eq!(
        state.dust.wallet_balance(state.time),
        CNIGHT_BAL * INITIAL_DUST_PARAMETERS.night_dust_ratio as u128
    );
    state
        .apply_system_tx(&SystemTransaction::CNightGeneratesDustUpdate {
            events: vec![CNightGeneratesDustEvent {
                action: midnight_ledger::structure::CNightGeneratesDustActionType::Destroy,
                nonce,
                owner: DustPublicKey::from(state.dust_key.clone()),
                time: state.time,
                value: CNIGHT_BAL,
            }],
        })
        .unwrap();
    let empty_tx: Transaction<Signature, _, _, _> =
        Transaction::new("local-test", Default::default(), None, Default::default());
    let tx = state
        .balance_tx(rng.split(), empty_tx, &RESOLVER)
        .await
        .unwrap();
    dbg!(&tx);
    let strictness = WellFormedStrictness::default();
    state.assert_apply(&tx, strictness);
    let last_bal = state.dust.wallet_balance(state.time);
    state.step();
    dbg!(last_bal);
    dbg!(state.dust.wallet_balance(state.time));
    assert!(state.dust.wallet_balance(state.time) < last_bal);
    state.fast_forward(INITIAL_DUST_PARAMETERS.time_to_cap());
    assert_eq!(state.dust.wallet_balance(state.time), 0);
    assert!(state.dust.utxos().next().is_none());
}

#[tokio::test]
async fn test_cycle_transfers() {
    // Test Night UTXOs being cycled through Y participants
    // Each participant gets one UTXO to start, then each participant takes turn to move their
    // current UTXO one participant to the right.
    //
    // We end when one full 'cycle' has been completed.
    // This stress-tests the wallet's utxo management, and tree sparsity, by ensuring plenty of
    // sparse insertions and deletions need to take place. We only track the first participant
    // (Alice)'s wallet state, but this will be sparse, as it doesn't see most interactions, and
    // further, interactions do not spend the most recent UTXOs.

    let mut rng = StdRng::seed_from_u64(0x42);
    // Initial states
    let mut state: TestState<InMemoryDB> = TestState::new(&mut rng);
    let alice_vk = state.night_key.verifying_key();
    let alice_addr = UserAddress::from(alice_vk.clone());
    let alice_dust = DustPublicKey::from(state.dust_key.clone());

    const NIGHT_VAL: u128 = 1_000_000_000;
    const CYCLE_LEN: usize = 128;

    let mut cycle = vec![(alice_vk.clone(), alice_addr, alice_dust)];
    for _ in 1..CYCLE_LEN {
        let sk = SigningKey::sample(&mut rng);
        let vk = sk.verifying_key();
        let addr = UserAddress::from(vk.clone());
        let dust = DustPublicKey(rng.r#gen());
        cycle.push((vk, addr, dust));
    }

    state
        .reward_night(&mut rng, CYCLE_LEN as u128 * NIGHT_VAL)
        .await;
    state.fast_forward(INITIAL_DUST_PARAMETERS.time_to_cap());

    let utxo_ih = state.ledger.utxo.utxos.iter().next().unwrap().0.intent_hash;

    // Mint to Alice, register all for DUST
    let mut intent = Intent::<Signature, _, _, _>::empty(&mut rng, state.time);
    let mut outputs = cycle
        .iter()
        .enumerate()
        .map(|(i, (_, addr, _))| {
            (
                UtxoOutput {
                    owner: *addr,
                    type_: NIGHT,
                    value: NIGHT_VAL,
                },
                i,
            )
        })
        .collect::<Vec<_>>();
    outputs.sort();
    intent.guaranteed_unshielded_offer = Some(Sp::new(UnshieldedOffer {
        inputs: vec![UtxoSpend {
            intent_hash: utxo_ih,
            output_no: 0,
            owner: alice_vk,
            type_: NIGHT,
            value: NIGHT_VAL * CYCLE_LEN as u128,
        }]
        .into(),
        outputs: outputs.iter().map(|(out, _)| out.clone()).collect(),
        signatures: vec![].into(),
    }));
    intent.dust_actions = Some(Sp::new(DustActions {
        spends: vec![].into(),
        registrations: cycle
            .iter()
            .map(|(night, _, dust)| DustRegistration {
                allow_fee_payment: 0,
                dust_address: Some(Sp::new(*dust)),
                night_key: night.clone(),
                signature: None,
            })
            .collect(),
        ctime: state.time,
    }));
    let utxo_ih = intent.erase_proofs().erase_signatures().intent_hash(0);
    let mut utxos = vec![VecDeque::new(); cycle.len()];
    for (j, (_, i)) in outputs.iter().enumerate() {
        utxos[*i].push_back((utxo_ih, j as u32));
    }
    let tx = Transaction::from_intents("local-test", [(1, intent)].into_iter().collect());
    let mut unbalanced_strictness = WellFormedStrictness::default();
    unbalanced_strictness.enforce_balancing = false;
    unbalanced_strictness.verify_signatures = false;
    state.assert_apply(&tx, unbalanced_strictness);

    // Cycle n times
    const N: usize = 4;
    for i in 0..CYCLE_LEN * N {
        let sender = cycle[i % CYCLE_LEN].0.clone();
        let recipient = cycle[(i + 1) % CYCLE_LEN].1;
        let utxo = utxos[i % CYCLE_LEN].pop_front().unwrap();
        let mut intent = Intent::<Signature, _, _, _>::empty(&mut rng, state.time);
        intent.guaranteed_unshielded_offer = Some(Sp::new(UnshieldedOffer {
            inputs: vec![UtxoSpend {
                intent_hash: utxo.0,
                output_no: utxo.1,
                owner: sender,
                type_: NIGHT,
                value: NIGHT_VAL,
            }]
            .into(),
            outputs: vec![UtxoOutput {
                owner: recipient,
                type_: NIGHT,
                value: NIGHT_VAL,
            }]
            .into(),
            signatures: vec![].into(),
        }));
        let utxo_ih = intent.erase_proofs().erase_signatures().intent_hash(0);
        utxos[(i + 1) % CYCLE_LEN].push_back((utxo_ih, 0));
        let tx = Transaction::from_intents("local-test", [(1, intent)].into_iter().collect());
        let t0 = std::time::Instant::now();
        state.assert_apply(&tx, unbalanced_strictness);
        let t1 = std::time::Instant::now();
        dbg!(t1 - t0);
    }
    state.fast_forward(state.ledger.parameters.dust.time_to_cap());
    let tx =
        Transaction::<Signature, _, _, _>::from_intents("local-test", [].into_iter().collect());
    let tx = tx_prove_bind(rng.split(), &tx, &RESOLVER).await.unwrap();
    let tx = state.balance_tx(rng.split(), tx, &RESOLVER).await.unwrap();
    let strictness = WellFormedStrictness::default();
    state.assert_apply(&tx, strictness);
}

/// VERIFY #1: a multi-UTXO wallet can register all its NIGHT for dust via SEPARATE
/// registration txs for the SAME night key (one NIGHT input each, to stay under the
/// time-to-dismiss budget). Confirms (a) the 2nd registration is accepted, and (b)
/// BOTH UTXOs end up generating dust.
#[tokio::test]
async fn test_two_registrations_same_key_both_generate() {
    let mut rng = StdRng::seed_from_u64(0x77);
    let mut state: TestState<InMemoryDB> = TestState::new(&mut rng);
    let strictness = WellFormedStrictness::default();
    let verifying_key = state.night_key.verifying_key();
    let addr = UserAddress::from(verifying_key.clone());

    const NIGHT_VAL: u128 = 1_000_000;
    const DUST_VAL: u128 = NIGHT_VAL * INITIAL_DUST_PARAMETERS.night_dust_ratio as u128;

    // Two separate NIGHT UTXOs under the same night key.
    state.reward_night(&mut rng, NIGHT_VAL).await;
    state.reward_night(&mut rng, NIGHT_VAL).await;
    state.fast_forward(INITIAL_DUST_PARAMETERS.time_to_cap());

    let utxos: Vec<(_, u32)> = state
        .ledger
        .utxo
        .utxos
        .iter()
        .map(|sp| (sp.0.intent_hash, sp.0.output_no))
        .collect();
    assert_eq!(utxos.len(), 2, "expected 2 NIGHT UTXOs");

    // Build a registration that spends one UTXO (1 input -> 1 output) + registers the key.
    let make_reg = |state: &TestState<InMemoryDB>, rng: &mut StdRng, ih, ono| {
        let mut intent = Intent::<(), _, _, _>::empty(rng, state.time);
        intent.guaranteed_unshielded_offer = Some(Sp::new(UnshieldedOffer {
            inputs: vec![UtxoSpend {
                intent_hash: ih,
                output_no: ono,
                owner: verifying_key.clone(),
                type_: NIGHT,
                value: NIGHT_VAL,
            }]
            .into(),
            outputs: vec![UtxoOutput { owner: addr.clone(), type_: NIGHT, value: NIGHT_VAL }].into(),
            signatures: vec![].into(),
        }));
        intent.dust_actions = Some(Sp::new(DustActions {
            spends: vec![].into(),
            registrations: vec![DustRegistration {
                allow_fee_payment: DUST_VAL,
                dust_address: Some(Sp::new(DustPublicKey::from(state.dust_key.clone()))),
                night_key: verifying_key.clone(),
                signature: None,
            }]
            .into(),
            ctime: state.time,
        }));
        let intent = intent
            .sign(rng, 1, &[state.night_key.clone()], &[], &[state.night_key.clone()])
            .unwrap();
        Transaction::from_intents("local-test", [(1, intent)].into_iter().collect())
    };

    // --- Registration 1: UTXO A ---
    let tx1 = make_reg(&state, &mut rng, utxos[0].0, utxos[0].1);
    let r1 = state.apply(&tx1, strictness).unwrap();
    assert!(matches!(r1, TransactionResult::Success(_)), "reg1 must succeed");
    let gen_1 = state.dust.utxos().count();
    let bal_1 = state.dust.wallet_balance(state.time);
    eprintln!("after reg1: generating_utxos={gen_1}, dust_balance={bal_1}");

    // --- Registration 2: UTXO B, SAME night key, SEPARATE tx ---
    let tx2 = make_reg(&state, &mut rng, utxos[1].0, utxos[1].1);
    let r2 = state.apply(&tx2, strictness);
    eprintln!("reg2 apply ok={:?}", r2.is_ok());
    let r2 = r2.expect("reg2 (same key, separate tx) must not error");
    assert!(matches!(r2, TransactionResult::Success(_)), "reg2 must succeed");
    let gen_2 = state.dust.utxos().count();
    let bal_2 = state.dust.wallet_balance(state.time);
    eprintln!("after reg2: generating_utxos={gen_2}, dust_balance={bal_2}");

    assert_eq!(gen_2, 2, "BOTH UTXOs must generate dust after two registrations");
    assert!(bal_2 > bal_1, "dust balance must grow when the 2nd UTXO is registered");

    // VERIFY the FFI filter's matching key: every generating dust UTXO's
    // backing_night equals exactly one current NIGHT UTXO's initial_nonce, and the
    // NIGHT UTXOs NOT matched are the unregistered ones. This is the identity
    // `dust_filter_unregistered_night` relies on.
    let backing: Vec<[u8; 32]> = state.dust.utxos().map(|u| u.backing_night.0 .0).collect();
    let night_matches = state
        .ledger
        .utxo
        .utxos
        .iter()
        .filter(|sp| sp.0.type_ == NIGHT)
        .filter(|sp| backing.contains(&sp.0.initial_nonce().0 .0))
        .count();
    assert_eq!(
        night_matches, 2,
        "both registered NIGHT UTXOs' initial_nonce must match a dust backing_night"
    );
}
