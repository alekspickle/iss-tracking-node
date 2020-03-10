use codec::{Decode, Encode};
/// A runtime module template with necessary imports

/// Feel free to remove or edit this file as needed.
/// If you change the name of this file, make sure to update its references in runtime/src/lib.rs
/// If you remove this file, you can remove those references

/// For more guidance on Substrate modules, see the example module
/// https://github.com/paritytech/substrate/blob/master/frame/example/src/lib.rs
use frame_support::{
    debug, decl_event, decl_module, decl_storage, dispatch::DispatchResult, traits::Get,
    weights::SimpleDispatchInfo,
};
use offchain::SubmitUnsignedTransaction;
// use serde_json as json;
use simple_json::{self, json::JsonValue};
#[allow(unused)]
use num_traits::float::FloatCore;

use sp_core::{crypto::KeyTypeId, offchain::Duration};
use sp_runtime::{
    offchain::http,
    transaction_validity::{InvalidTransaction, TransactionValidity, ValidTransaction},
};
use sp_std::prelude::*;
use system::{ensure_none, offchain};

#[derive(Encode, Decode, Default, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct ISSPosition {
    timestamp: u64,
    latitude: u64,
    longitude: u64,
}

/// Defines application identifier for crypto keys of this module.
///
/// Every module that deals with signatures needs to declare its unique identifier for
/// its crypto keys.
/// When offchain worker is signing transactions it's going to request keys of type
/// `KeyTypeId` from the keystore and use the ones it finds to sign the transaction.
/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"btc!");

/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrappers.
/// We can use from supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
/// the types with this pallet-specific identifier.
pub mod crypto {
    use super::KEY_TYPE;
    use sp_runtime::app_crypto::{app_crypto, sr25519};
    app_crypto!(sr25519, KEY_TYPE);
}

/// The module's configuration trait.
pub trait Trait: system::Trait + timestamp::Trait {
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    type Call: From<Call<Self>>;
    type SubmitUnsignedTransaction: SubmitUnsignedTransaction<Self, <Self as Trait>::Call>;

    // Wait period between automated fetches. Set to 0 disable this feature.
    //   Then you need to manucally kickoff positionfetch
    type BlockFetchPeriod: Get<Self::BlockNumber>;

    /// Number of blocks of cooldown after unsigned transaction is included.
    ///
    /// This ensures that we only accept unsigned transactions once, every `UnsignedInterval` blocks.
    type UnsignedInterval: Get<Self::BlockNumber>;
}

// This module's storage items.
decl_storage! {
    trait Store for Module<T: Trait> as ISSTracker {

        History get(fn history): Vec<ISSPosition>;
        CurrentPosition get(fn current_position): ISSPosition;

        /// Defines the block when next unsigned transaction will be accepted.
        ///
        /// To prevent spam of unsigned (and unpayed!) transactions on the network,
        /// we only allow one transaction every `T::UnsignedInterval` blocks.
        /// This storage entry defines when new transaction is going to be accepted.
        NextUnsignedAt get(fn next_unsigned_at): T::BlockNumber;
    }
}

// The module's dispatchable functions.
decl_module! {
    /// The module declaration.
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        #[weight = SimpleDispatchInfo::FixedNormal(10_000)]
        pub fn submit_position_unsigned(origin, _block_number: T::BlockNumber, position: (u64,u64,u64))
            -> DispatchResult
        {
            ensure_none(origin)?;
            Self::add_position(position);

            // now increment the block number at which we expect next unsigned transaction.
            let current_block = <system::Module<T>>::block_number();
            <NextUnsignedAt<T>>::put(current_block + T::UnsignedInterval::get());
            Ok(())
        }

        /// Offchain Worker entry point.
        fn offchain_worker(block_number: T::BlockNumber) {
            debug::native::info!("Fetching new International Space Station coordinates...");

           let res = Self::fetch_new_coordinates_and_send_unsigned(block_number);

           match res {
               Ok(()) => debug::info!("Successfully fetched new location!"),
               Err(e) => debug::error!("Error fetching new location: {:?}", e),
           }
        }
    }
}

decl_event!(
    pub enum Event<T>
    where
        Moment = <T as timestamp::Trait>::Moment,
    {
        PositionStored(Moment),
    }
);

impl<T: Trait> Module<T> {
    fn fetch_new_coordinates_and_send_unsigned(
        block_number: T::BlockNumber,
    ) -> Result<(), &'static str> {
        // Make sure we don't fetch the position if unsigned transaction is going to be rejected
        // anyway.
        // let next_unsigned_at = <NextUnsignedAt<T>>::get();
        // if next_unsigned_at > block_number {
        //     return Err(format!(
        //         "Too early to send unsigned transaction. Next at: {:?}",
        //         next_unsigned_at
        //     ))?;
        // }

        // let position = Self::fetch_new_coordinates().map_err(|e| format!("{:?}", e))?;
        let position =
            Self::fetch_new_coordinates().map_err(|_e| "Could not fetch coordinates.")?;
        debug::debug!("FROM fetch_new_coordinates_and_send_unsigned {:?}", position);
        // Received position is wrapped into a call to `submit_position_unsigned` public function of this
        // pallet. This means that the transaction, when executed, will simply call that function
        // passing `position` as an argument.
        let call = Call::submit_position_unsigned(block_number, position);

        // Now let's create an unsigned transaction out of this call and submit it to the pool.
        // By default unsigned transactions are disallowed, so we need to whitelist this case
        // by writing `UnsignedValidator`. Note that it's EXTREMELY important to carefuly
        // implement unsigned validation logic, as any mistakes can lead to opening DoS or spam
        // attack vectors. See validation logic docs for more details.
        T::SubmitUnsignedTransaction::submit_unsigned(call)
            .map_err(|()| "Unable to submit unsigned transaction.".into())
    }
    fn fetch_new_coordinates() -> Result<(u64, u64, u64), http::Error> {
        let json = Self::fetch_json()?;

        let position = Self::format_position(json);
        let position = match position {
            Ok(position) => position,
            Err(e) => {
                debug::warn!("Unable to extract position from the response: {:?}", e);
                (0, 0, 0)
            }
        };

        match position {
            (0, 0, 0) => Err(http::Error::Unknown),
            (a, b, c) => {
                debug::warn!(
                    "Got position: lat:{}; lng:{}. Time: {}",
                    position.0,
                    position.1,
                    position.2
                );

                Ok((a, b, c))
            }
        }
    }
    
    fn fetch_json() -> Result<JsonValue, http::Error> {
        let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));

        let request = http::Request::get("http://api.open-notify.org/iss-now.json");
        let pending = request
            .deadline(deadline)
            .send()
            .map_err(|_| http::Error::IoError)?;

        let response = pending
            .try_wait(deadline)
            .map_err(|_| http::Error::DeadlineReached)??;

        if response.code != 200 {
            debug::warn!("Unexpected status code: {}", response.code);
            return Err(http::Error::Unknown);
        }

        let body = response.body().collect::<Vec<u8>>();

        let val: JsonValue = simple_json::parse_json(
            &core::str::from_utf8(&body)
                .map_err(|_| http::Error::IoError)?,
        )
        .map_err(|_| http::Error::IoError)?;

        // let val: Result<JsonValue, _> = json::from_slice(&body);
        // let val = match val {
        //     Ok(v) => v,
        //     Err(e) => return Err(http::Error::IoError),
        // };
        Ok(val)
    }

    /// Add new position to the list.
    fn add_position(position: (u64, u64, u64)) {
        debug::info!("Adding to the history: {:?}", position);
        let new = ISSPosition {
            latitude: position.0,
            longitude: position.1,
            timestamp: position.2,
        };
        CurrentPosition::put(new.clone());
        History::mutate(|positions| positions.push(new));

        Self::deposit_event(RawEvent::PositionStored(<timestamp::Module<T>>::get()));
    }

    // // format incoming json
    // fn format_position(json: JsonValue) -> Result<(u64, u64, u64), &'static str> {
    //     // Expected JSON shape:
    //     //   r#"{"iss_position": {"longitude": "-34.4742", "latitude": "38.3724"}, "timestamp": 1583828326, "message": "success"}"#;
    //     let timestamp = json["timestamp"].as_u64().expect("error extracting field");
    //     let position = json["iss_position"];
    //     let lat = position["lat"].as_u64().expect("error extracting field");
    //     let lng = position["lng"].as_u64().expect("error extracting field");
    //     // let timestamp = json
    //     //     .ok()
    //     //     .and_then(|v| v.get("timestamp").and_then(|v| v.as_u64()));
    //     // let position = json.ok().and_then(|v| v.get("iss_position"));
    //     // let lat = position.and_then(|v| v.get("lat").and_then(|v| v.as_u64()));
    //     // let lng = position.and_then(|v| v.get("lng").and_then(|v| v.as_u64()));

    //     debug::debug!("POSITION lat:{} lng:{}", lat, lng);
    //     Ok((lat, lng, timestamp))
    // }
    
    // format incoming json
    fn format_position(value: JsonValue) -> Result<(u64, u64, u64), &'static str> {
        // Expected JSON shape:
        //   r#"{"iss_position": {"longitude": "-34.4742", "latitude": "38.3724"}, "timestamp": 1583828326, "message": "success"}"#;
        // Expected JSON shape:
        //   r#"{"cdai":{"usd": 7064.16}}"#;
        debug::info!("111111 {:?}", value);
        let position = value.get_object()[2].1.get_object().clone();
        debug::info!("position {:?}", position);
        let lat = position[0].1.get_string().parse::<f64>().expect("could not parse position json");
        let lng = position[1].1.get_string().parse::<f64>().expect("could not parse position json");
        debug::debug!("POSITION lat:{} lng:{}", lat, lng);
        let timestamp = value.get_object()[1].1.get_number_f64();
        let lat = Self::round_value(lat);
        let lng = Self::round_value(lng);
        let time = Self::round_value(timestamp);
        debug::debug!("POSITION lat:{} lng:{}", lat, lng);
        Ok((lat, lng, time))
    }

    fn round_value(v: f64) -> u64 {
        (v * 10000.).round() as u64
    }
}

#[allow(deprecated)]
impl<T: Trait> frame_support::unsigned::ValidateUnsigned for Module<T> {
    type Call = Call<T>;

    /// Validate unsigned call to this module.
    ///
    /// By default unsigned transactions are disallowed, but implementing the validator
    /// here we make sure that some particular calls (the ones produced by offchain worker)
    /// are being whitelisted and marked as valid.
    fn validate_unsigned(call: &Self::Call) -> TransactionValidity {
        if let Call::submit_position_unsigned(block_number, _new_position) = call {
            // Now let's check if the transaction has any chance to succeed.
            let next_unsigned_at = <NextUnsignedAt<T>>::get();
            if &next_unsigned_at > block_number {
                return InvalidTransaction::Stale.into();
            }
            // Let's make sure to reject transactions from the future.
            let current_block = <system::Module<T>>::block_number();
            if &current_block < block_number {
                return InvalidTransaction::Future.into();
            }

            Ok(ValidTransaction {
                priority: 0,
                requires: vec![],
                // We set the `provides` tag to be the same as `next_unsigned_at`. This makes
                // sure only one transaction produced after `next_unsigned_at` will ever
                // get to the transaction pool and will end up in the block.
                provides: vec![codec::Encode::encode(&(KEY_TYPE.0, next_unsigned_at))],
                // After 5 blocks, tx is going to be revalidated by the pool.
                longevity: 5,
                // Restrict to block producers only
                propagate: true,
            })
        } else {
            InvalidTransaction::Call.into()
        }
    }
}

/// tests for this module
#[cfg(test)]
mod tests {
    use super::*;

    use frame_support::{assert_ok, impl_outer_origin, parameter_types, weights::Weight};
    use sp_core::H256;
    use sp_runtime::{
        testing::Header,
        traits::{BlakeTwo256, IdentityLookup},
        Perbill,
    };

    impl_outer_origin! {
        pub enum Origin for Test {}
    }

    // For testing the module, we construct most of a mock runtime. This means
    // first constructing a configuration type (`Test`) which `impl`s each of the
    // configuration traits of modules we want to use.
    #[derive(Clone, Eq, PartialEq)]
    pub struct Test;
    parameter_types! {
        pub const BlockHashCount: u64 = 250;
        pub const MaximumBlockWeight: Weight = 1024;
        pub const MaximumBlockLength: u32 = 2 * 1024;
        pub const AvailableBlockRatio: Perbill = Perbill::from_percent(75);
    }
    impl system::Trait for Test {
        type Origin = Origin;
        type Call = ();
        type Index = u64;
        type BlockNumber = u64;
        type Hash = H256;
        type Hashing = BlakeTwo256;
        type AccountId = u64;
        type Lookup = IdentityLookup<Self::AccountId>;
        type Header = Header;
        type Event = ();
        type BlockHashCount = BlockHashCount;
        type MaximumBlockWeight = MaximumBlockWeight;
        type MaximumBlockLength = MaximumBlockLength;
        type AvailableBlockRatio = AvailableBlockRatio;
        type Version = ();
        type ModuleToIndex = ();
    }
    impl Trait for Test {
        type Event = ();
    }
    type Rock = Module<Test>;

    // This function basically just builds a genesis storage key/value store according to
    // our desired mockup.
    fn new_test_ext() -> sp_io::TestExternalities {
        system::GenesisConfig::default()
            .build_storage::<Test>()
            .unwrap()
            .into()
    }

    #[test]
    fn it_works_for_default_value() {
        new_test_ext().execute_with(|| {
            // Just a dummy test for the dummy funtion `do_something`
            // calling the `do_something` function with a value 42
            assert_ok!(Rock::do_something(Origin::signed(1), 42));
            // asserting that the stored value is equal to what we stored
            assert_eq!(Rock::something(), Some(42));
        });
    }
}
