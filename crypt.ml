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
      let nssli = List.append [deriveMd5 data] strli in
      derive nssli (i + 1) (lilen + 1)
    end
  in derive [] 0 0

let prng () = Random.pseudo_rng (Random.string Random.secure_rng 20)


module AES_Cipher = struct

  type t

  let encryptor ~key ~iv ~plain = 
    let encBox = Cipher.aes ~pad:Padding.length ~iv key Cipher.Encrypt in
    return (transform_string encBox plain)

  let decryptor ~key ~iv ~cipher =
    let decBox = Cipher.aes ~pad:Padding.length ~iv key Cipher.Decrypt in
    return (transform_string decBox cipher)
end



module AES_Cipher_RandomIV = struct

  type t

  let encryptor_r ~key ~plain ~prng =
    let riv = Random.string prng 16 in
    let encbox = 
      return (Cipher.aes ~pad:Padding.length ~iv:riv key Cipher.Encrypt) in
    Deferred.both encbox plain >>|
    fun (encrypt, plaintext) -> (riv ^ (transform_string encrypt plaintext))

  let decryptor_r ~key ~cipher =
    let decbox = (cipher >>| (fun ctext -> String.slice ctext 0 16)) >>|
    (fun iv -> Cipher.aes ~pad:Padding.length ~iv key Cipher.Decrypt) in
    let ctext = (cipher >>| 
      fun ctext -> String.slice ctext 16 (String.length ctext)) in
    Deferred.both decbox ctext >>|
    (fun (decrypt, ciphertext) -> transform_string decrypt ciphertext)
end