//! Reshare Threshold Scheme

use alloc::collections::btree_map::BTreeMap;
use alloc::collections::btree_set::BTreeSet;

use crate::keys::{KeyPackage, PublicKeyPackage};
use crate::{frost, Identifier, SigningKey, };
use crate::{Error, CryptoRng, RngCore};

use super::SecretShare;


pub use super::refresh::*;

/// 
pub fn compute_new_participant_subshare<R: RngCore + CryptoRng>(
    old_key_package: &KeyPackage,
    old_id_set: &BTreeSet<Identifier>, 
    max_signers: u16,
    min_signers: u16,
    mut rng: R,
    new_identifier: Identifier,
) -> Result<SecretShare, Error> {
    frost::keys::reshare::compute_new_participant_subshare(old_key_package,  old_id_set, min_signers, max_signers, &mut rng, new_identifier)
}

/// 
pub fn reconstruct_key_from_subshares(helper_shares: BTreeMap<Identifier, SecretShare>, new_identifier: Identifier, new_participants: &BTreeSet<Identifier>) -> Result<(KeyPackage, PublicKeyPackage), Error>{
    frost::keys::reshare::reconstruct_key_from_subshares(helper_shares, new_identifier, new_participants)
}

#[cfg(test)]
mod tests {
    use alloc::collections::btree_map::BTreeMap;
    use alloc::collections::btree_set::BTreeSet;
    use alloc::vec::Vec;
    use frost_core::{compute_lagrange_coefficient, Element, Group, SigningKey};

    use crate::keys::reshare::{compute_new_participant_subshare, reconstruct_key_from_subshares, refresh_dkg_part1, refresh_dkg_part2, refresh_dkg_shares};
    use crate::keys::PublicKeyPackage;
    use crate::{aggregate, round1, round2, Identifier, Secp256K1Sha256, SigningPackage};

    #[test]
    fn test_reshare() -> Result<(), crate::Error> {

        let mut rng = rand::rngs::OsRng;

        let max_signers = 5;
        let min_signers = 3;

        ////////////////////////////////////////////////////////////////////////////
        // Key generation, Round 1
        ////////////////////////////////////////////////////////////////////////////

        // Keep track of each participant's round 1 secret package.
        // In practice each participant will keep its copy; no one
        // will have all the participant's packages.
        let mut round1_secret_packages = BTreeMap::new();

        // Keep track of all round 1 packages sent to the given participant.
        // This is used to simulate the broadcast; in practice the packages
        // will be sent through some communication channel.
        let mut received_round1_packages = BTreeMap::new();

        // For each participant, perform the first part of the DKG protocol.
        // In practice, each participant will perform this on their own environments.
        for participant_index in 1..=max_signers {
            let participant_identifier = participant_index.try_into().expect("should be nonzero");
            // ANCHOR: dkg_part1
            let (round1_secret_package, round1_package) = crate::frost::keys::dkg::part1(
                participant_identifier,
                max_signers,
                min_signers,
                &mut rng,
            )?;
            // ANCHOR_END: dkg_part1

            // Store the participant's secret package for later use.
            // In practice each participant will store it in their own environment.
            round1_secret_packages.insert(participant_identifier, round1_secret_package);

            // "Send" the round 1 package to all other participants. In this
            // test this is simulated using a BTreeMap; in practice this will be
            // sent through some communication channel.
            for receiver_participant_index in 1..=max_signers {
                if receiver_participant_index == participant_index {
                    continue;
                }
                let receiver_participant_identifier: Identifier = receiver_participant_index
                    .try_into()
                    .expect("should be nonzero");
                received_round1_packages
                    .entry(receiver_participant_identifier)
                    .or_insert_with(BTreeMap::new)
                    .insert(participant_identifier, round1_package.clone());
            }
        }

        ////////////////////////////////////////////////////////////////////////////
        // Key generation, Round 2
        ////////////////////////////////////////////////////////////////////////////

        // Keep track of each participant's round 2 secret package.
        // In practice each participant will keep its copy; no one
        // will have all the participant's packages.
        let mut round2_secret_packages = BTreeMap::new();

        // Keep track of all round 2 packages sent to the given participant.
        // This is used to simulate the broadcast; in practice the packages
        // will be sent through some communication channel.
        let mut received_round2_packages = BTreeMap::new();

        // For each participant, perform the second part of the DKG protocol.
        // In practice, each participant will perform this on their own environments.
        for participant_index in 1..=max_signers {
            let participant_identifier = participant_index.try_into().expect("should be nonzero");
            let round1_secret_package = round1_secret_packages
                .remove(&participant_identifier)
                .unwrap();
            let round1_packages = &received_round1_packages[&participant_identifier];
            // ANCHOR: dkg_part2
            let (round2_secret_package, round2_packages) =
                crate::frost::keys::dkg::part2(round1_secret_package, round1_packages)?;
            // ANCHOR_END: dkg_part2

            // Store the participant's secret package for later use.
            // In practice each participant will store it in their own environment.
            round2_secret_packages.insert(participant_identifier, round2_secret_package);

            // "Send" the round 2 package to all other participants. In this
            // test this is simulated using a BTreeMap; in practice this will be
            // sent through some communication channel.
            // Note that, in contrast to the previous part, here each other participant
            // gets its own specific package.
            for (receiver_identifier, round2_package) in round2_packages {
                received_round2_packages
                    .entry(receiver_identifier)
                    .or_insert_with(BTreeMap::new)
                    .insert(participant_identifier, round2_package);
            }
        }

        ////////////////////////////////////////////////////////////////////////////
        // Key generation, final computation
        ////////////////////////////////////////////////////////////////////////////

        // Keep track of each participant's long-lived key package.
        // In practice each participant will keep its copy; no one
        // will have all the participant's packages.
        let mut key_packages = BTreeMap::new();
        let mut refresh_key_packages = key_packages.clone();

        // Keep track of each participant's public key package.
        // In practice, if there is a Coordinator, only they need to store the set.
        // If there is not, then all candidates must store their own sets.
        // All participants will have the same exact public key package.
        let mut pubkey_packages = BTreeMap::new();
        let mut refresh_pubkey_packages = pubkey_packages.clone();

        // For each participant, perform the third part of the DKG protocol.
        // In practice, each participant will perform this on their own environments.
        for participant_index in 1..=max_signers {
            let participant_identifier = participant_index.try_into().expect("should be nonzero");
            let round2_secret_package = &round2_secret_packages[&participant_identifier];
            let round1_packages = &received_round1_packages[&participant_identifier];
            let round2_packages = &received_round2_packages[&participant_identifier];
            // ANCHOR: dkg_part3
            let (key_package, pubkey_package) = crate::frost::keys::dkg::part3(
                round2_secret_package,
                round1_packages,
                round2_packages,
            )?;
            // ANCHOR_END: dkg_part3
            key_packages.insert(participant_identifier, key_package);
            pubkey_packages.insert(participant_identifier, pubkey_package);
        }

        // reconstruct the new participant's key package

        // let new_identifier: Identifier = (max_signers + 1).try_into().expect("should be nonzero");
        let x_set = (2..=max_signers).map(|i| (i as u16).try_into().expect("should be nonzero") ).collect::<BTreeSet<Identifier>>();
        let x_set_all = (2..=max_signers + 1).map(|i| (i as u16).try_into().expect("should be nonzero") ).collect::<BTreeSet<Identifier>>();
        
        for new_index in 2..=max_signers + 1 {

            let renew_identifier: Identifier = (new_index as u16).try_into().expect("should be nonzero");
            let mut received_recovered_shares = BTreeMap::new();

            for participant_index in 2..=max_signers {
                let helper_i = participant_index.try_into().expect("should be nonzero");
                let old_key_package = key_packages.get(&helper_i).expect("should exist");
                // let old_signing_key = SigningKey::from_scalar(old_keypackage.signing_share().to_scalar()).expect("should work");
                let share_i = compute_new_participant_subshare(
                    &old_key_package,
                    &x_set,
                    max_signers,
                    min_signers,
                    rng,
                    renew_identifier
                )?;

                received_recovered_shares.insert(helper_i, share_i);
            }

            let (new_keypackage, new_pubkeypackage) = reconstruct_key_from_subshares(received_recovered_shares, renew_identifier, &x_set_all)?;

            if let Some(old_pubkey)= pubkey_packages.get(&renew_identifier) {
                assert_eq!(old_pubkey.verifying_key(), new_pubkeypackage.verifying_key(), "should have all verifying shares");
            };

            refresh_key_packages.insert(renew_identifier, new_keypackage);
            refresh_pubkey_packages.insert(renew_identifier, new_pubkeypackage);

        }
        
        // let mut vss = BTreeMap::new();

        // // update new verifying shares for participants
        // for (id, sk) in &refresh_key_packages {
        //     vss.insert(*id, sk.verifying_share().clone());
        // }

        // let x_set = refresh_key_packages.keys().map(|i| *i ).collect::<BTreeSet<_>>();
        // let mut verify_key = <<Secp256K1Sha256TR as frost_core::Ciphersuite>::Group as Group>::Element::identity();
        // for (id, sk) in &refresh_key_packages {
        //     let lamda_i0 = compute_lagrange_coefficient(&x_set, None, *id).expect("should work");
        //     let new_verifying_share = sk.verifying_share().to_element() * lamda_i0;
        //     verify_key = verify_key + new_verifying_share;
        // }

        // for (id, sk) in &refresh_key_packages {
        //     // assert_eq!(sk.verifying_key().to_element(), verify_key, "verifying key should match");
        //     let pubkey_package = PublicKeyPackage::new(vss.clone(), sk.verifying_key().clone());
        //     refresh_pubkey_packages.insert(*id, pubkey_package);
        // }


        ////////////////////////////////////////////////////////////////////////////
        // Sign, Round 1
        ////////////////////////////////////////////////////////////////////////////

        let message = b"Hello, world!";
        let mut signing_commitments = BTreeMap::new();
        let mut signing_nonces = BTreeMap::new();
        let mut signature_shares = BTreeMap::new();

        for participant_index in 2..=max_signers + 1 {

            let participant_identifier = participant_index.try_into().expect("should be nonzero");
            let keypackage = refresh_key_packages.get(&participant_identifier).expect("priv key should exist");
            let (nonce, commitment) = round1::commit(keypackage.signing_share(), &mut rng);

            signing_nonces.insert(participant_identifier, nonce);
            signing_commitments.insert(participant_identifier, commitment);

        }

        for participant_index in 2..=max_signers + 1 {

            let participant_identifier = participant_index.try_into().expect("should be nonzero");
            let keypackage = refresh_key_packages.get(&participant_identifier).expect("priv should exist");

            let signing_package = SigningPackage::new(signing_commitments.clone(), message);
            let signing_nonce = signing_nonces.get(&participant_identifier).expect("nonce should exist");

            let signature_share = round2::sign(&signing_package, signing_nonce , keypackage)?;
            signature_shares.insert(participant_identifier, signature_share);
         }


        //for participant_index in 2..=max_signers + 1 {

            let to_verify_id: Identifier = (3 as u16).try_into().expect("should be nonzero");
            // let participant_identifier = participant_index.try_into().expect("should be nonzero");
            let pubkey_package = refresh_pubkey_packages.get(&to_verify_id).expect("pub key should exist");


            let signing_package = SigningPackage::new(signing_commitments.clone(), message);
            let signature = aggregate(&signing_package, &signature_shares, pubkey_package)?;
            // let v = pubkey_package.verifying_key().verify(&message, signature);

            let pubkey_package2 = refresh_pubkey_packages.get(&to_verify_id).expect("pub key should exist");
            assert!(pubkey_package2.verifying_key().verify(&message[..], &signature).is_ok(), "signature should verify");

        //}

        Ok(())

    }

}