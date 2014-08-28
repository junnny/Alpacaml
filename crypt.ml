(* Copyright (C) 2014 marklrh
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>. *)

open Core.Std
open Async.Std
open Cryptokit

let hex ~s = transform_string (Hexa.decode ()) s

let tohex ~s = transform_string (Hexa.encode ()) s

let deriveSha256 ~s = hash_string (Hash.sha256 ()) s

let deriveMd5 ~s = hash_string (Hash.md5 ()) s

let evpBytesToKey ~pwd ~key_len ~iv_len =
  let rec derive strli i lilen =
    if (16 * lilen) >= key_len + iv_len then begin
      let combinedStr = String.concat strli in
      let key = String.slice combinedStr 0 key_len
      and iv = String.slice combinedStr key_len (key_len + iv_len) in
      (key, iv)
    end else begin
      let data = 
        match List.nth strli i with 
        | None -> pwd
        | Some c -> (c ^ pwd)
      in 
      let nssli = List.append [deriveMd5 ~s:data] strli in
      derive nssli (i + 1) (lilen + 1)
    end
  in derive [] 0 0

let prng () = Random.pseudo_rng (Random.string Random.secure_rng 20)


module AES_Cipher = struct

  let encryptor ~key ~iv ~ptext = 
    let encBox = Cipher.aes ~pad:Padding.length ~iv key Cipher.Encrypt in
    return (transform_string encBox ptext)

  let decryptor ~key ~iv ~ctext  =
    let decBox = Cipher.aes ~pad:Padding.length ~iv key Cipher.Decrypt in
    return (transform_string decBox ctext)
end


module AES_256_CBC_RandomIV = struct

  let encryptor ~key ~prng ~ptext =
    return (Random.string prng 16) >>= (fun riv ->
      return (Cipher.aes ~pad:Padding.length ~iv:riv key Cipher.Encrypt) >>=
        (fun encbox -> return (transform_string encbox ptext) >>=
          (fun ctext -> return (riv ^ ctext))))

  let decryptor ~key ~iv ~ctext =
    return (Cipher.aes ~pad:Padding.length ~iv key Cipher.Decrypt) >>=
    (fun decbox -> return (transform_string decbox ctext))

end

open Sodium

module Libsodium = struct
  
  let get_nonce () = return (Box.random_nonce ())

  let gen_sk_pk () = return (Box.random_keypair ())

  let encryptor ~sk ~pk' ~ptext ~nonce = 
    return (Box.Bytes.box sk pk' ptext nonce)

  let decryptor ~sk ~pk' ~ctext ~nonce =
    return (Box.Bytes.box sk pk' ctext nonce)
  
  let sk_to_storage ~sk = 
    return (Box.Bytes.of_secret_key sk)

  let pk_to_storage ~pk = 
    return (Box.Bytes.of_public_key pk)
  
  let nonce_to_storage ~nonce =
    return (Box.Bytes.of_nonce nonce)

  let storage_to_sk ~storage =
    return (Box.Bytes.to_secret_key storage)

  let storage_to_pk ~storage =
    return (Box.Bytes.to_public_key storage)

  let stoarge_to_nonce ~storage =
    return (Box.Bytes.to_nonce storage)

  let compute_channel_key ~sk ~pk' = 
    return (Box.precompute sk pk')

  let fast_encryptor ~ck ~ptext ~nonce =
    return (Box.Bytes.fast_box ck ptext nonce)

  let fast_decryptor ~ck ~ctext ~nonce =
    return (Box.Bytes.fast_box_open ck ctext nonce)
end


