
use std::net::{SocketAddr, UdpSocket};
use serde::{Serialize, Deserialize};
use std::net::{IpAddr,Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use blake2::{Blake2b, Digest};

use sha2::Sha256;
use hmac::{Hmac, Mac, NewMac};
use pbkdf2::pbkdf2;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;


use aes::Aes128;
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use hex;
use std::collections::HashMap;

use config;

#[macro_use]
use serde_derive;

mod settings;

use settings::Settings;



// create an alias for convenience
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

// create an alias for convenience
type Aes256Cbc = Cbc<Aes256, Pkcs7>;


// #[derive(Encode, Decode, PartialEq, Debug)]
#[derive(Serialize, Deserialize, Debug)]
struct ProtoMessage{
    // Identifier is expected to be an e-mail or similar
    identifier: String,

    // ports to which access is requested
    request_access_ports :Vec<u16>,

    // source IP address from where the request generated
    // if the client is behind a NAT or having dynamic IP address, 
    // it should first find out its public IP address and fill it here
    // could be v4 or v6 address
    source_ip_addr :IpAddr,
    
    // ip address whre server is running and the client needs access to
    dst_ip_addr :IpAddr,
    
    // port where server is eapecting the message to arrive
    // although the server will never bind to that port, it is just one more thing for
    // MITM and replay attacks to figure out
    dst_port :u16,

    // time when message was created (it is the unix time in miliseconds)
    // too long a window between creation and reception of message means some MITM activities
    // packet will be ignored
    creation_time :u64,

    // version of message protocol
    version: u16
}

#[derive(Serialize, Deserialize, Debug)]
struct HmacProtoMessage{
    hmac_vec : Vec<u8>,
    message : Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct WireProtoMessage{
    client_id : String,
    enc_hmac_msg : Vec<u8>,
}


// static PRE_SHARED_KEY: &'static str = "6rHvrdTclgrRPOjclevU";
// static PRE_SHARED_IV: &'static str =  "OGyfuckihucc0R02Xd6i";


fn main() -> std::io::Result<()> {
    // Load the settings/configurations
    let settings :Settings; 
    match Settings::new(){
        Ok(setting) => {settings = setting; println!("{:?}", settings);},
        Err(e) => panic!("Could not find setting or load correctly {:?}",e)
    }
    

    let mut aes_key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(&settings.auth.pre_shared_key.as_bytes(), &settings.auth.pre_shared_iv.as_bytes(), 10, &mut aes_key);    
    let mut aes_iv = [0u8; 16];
    pbkdf2::<Hmac<Sha256>>(&settings.auth.pre_shared_iv.as_bytes(), &settings.auth.pre_shared_key.as_bytes(), 10, &mut aes_iv);
    let hasher = Blake2b::new();
    
    let localhost_v4 :IpAddr;
    match IpAddr::from_str(&settings.local.ip_address){
        Ok(localhost) => {localhost_v4 = localhost},
        Err(_) => panic!("Could not parse the local host IP address mentioned"),
    }
    
    let remotehost_v4 :IpAddr;
    match IpAddr::from_str(&settings.server.ip_address){
        Ok(remotehost) => {remotehost_v4 = remotehost},
        Err(_) => panic!("Could not parse the remote host IP address mentioned"),
    }
    
    let now :u64;
    // let bincode_config = Configuration::standard();
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => { now = n.as_secs(); println!("1970-01-01 00:00:00 UTC was {} seconds ago!", n.as_secs())},
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    }

    let req_message = ProtoMessage{
        identifier : settings.local.identifier.clone(),
        request_access_ports : settings.server.access_ports,
        source_ip_addr: localhost_v4,
        dst_ip_addr : remotehost_v4,
        dst_port : settings.server.server_port,
        creation_time : now,
        version : 1
    };
    println!("{:?}", req_message);
    // let serialized = serde_json::to_string(&req_message).unwrap();
    //bincode message size is 1/3rd of json, so we changed to bincode in server and 
    let bincode_serialized = bincode::serialize(&req_message).unwrap();

    // The serialized contains the parameters we want to send
    // We should now add HMAC
    // The message buffer with HMAC and the content together should then be encrypted
    // The AES pre-shared key encrypted content becomes payload for the message
    // println!("Serialized message: {}", serialized);
    println!("Serialized message: {:?}", bincode_serialized);
    // hasher.update(&bincode_serialized);
    // let hash = hasher.finalize();
    // let hash = Blake2b::digest(&bincode_serialized);
    // println!("Result: {:?}", hash);

    // Create HMAC-SHA256 instance which implements `Mac` trait
    let mut mac = HmacSha256::new_from_slice(&settings.auth.pre_shared_key.as_bytes())
                                .expect("HMAC can take key of any size");
    mac.update(&bincode_serialized);
    let result = mac.finalize();
    // `result` has type `Output` which is a thin wrapper around array of
    // bytes for providing constant time equality check
    // To get underlying array use `into_bytes` method, but be careful, since
    // incorrect use of the code value may permit timing attacks which defeat
    // the security provided by the `Output`
    let code_bytes = result.into_bytes();
    let hmac_message = HmacProtoMessage {
        hmac_vec : code_bytes.to_vec(),
        message : bincode_serialized.to_vec()
    };
    let bincode_serialized_hmac = bincode::serialize(&hmac_message).unwrap();

    {

        let addr_local = SocketAddr::new(localhost_v4, settings.local.local_port);
        let socket = UdpSocket::bind(&addr_local)
                            .expect("couldn't bind to address");

        let addr_remote = SocketAddr::new(remotehost_v4, settings.server.server_port);
        // socket.send_to(&serialized.as_str().as_bytes(), &addr_remote)
        //                     .expect("couldn't send to address");

        // the bincode_serialized_hmac has the actual message we want to send on the wire
        // we need to encrypt this before sending
        // on server side we will decrypt first
        // let aes_key = hex::encode(&PRE_SHARED_KEY); 
        // let aes_iv = hex::encode(&PRE_SHARED_IV); 
        // let cipher = Aes128Cbc::new_from_slices(&aes_key.as_bytes()[0..aes_key.len()], &aes_iv.as_bytes()[0..aes_key.len()]).unwrap();
        let cipher :Aes256Cbc; 
        // match Aes256Cbc::new_from_slices(&PRE_SHARED_KEY.as_bytes(), &PRE_SHARED_IV.as_bytes()){
        match Aes256Cbc::new_from_slices(&aes_key, &aes_iv){
            Ok(ciphe) => {
                cipher = ciphe;
            }
            Err(e) => panic!("{:?}", e)
        }
        
        let ciphertext = cipher.encrypt_vec(&bincode_serialized_hmac);
        let wire_proto_msg = WireProtoMessage{
            client_id : settings.local.client_id,
            enc_hmac_msg : ciphertext,
        };

        let bincode_serialized_wire = bincode::serialize(&wire_proto_msg).unwrap();
        // let mut msg = Vec::with_capacity(aes_iv.len() + ciphertext.len());
        // msg.extend_from_slice(&aes_iv);
        // msg.extend_from_slice(&ciphertext);
        socket.send_to(&bincode_serialized_wire, &addr_remote)
                            .expect("couldn't send to address");
    } // the socket is closed here
    Ok(())
}
