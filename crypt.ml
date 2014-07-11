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

(** derive 32-byte key from string of arbitrary size *)
let deriveSha256 ~s = hash_string (Hash.sha256 ()) s

(** derive 16-byte key from string of arbitrary size *)
let deriveMd5 ~s = hash_string (Hash.md5 ()) s

(** similar to OpenSSL's EVP_BytesToKey() *)
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


(** AES_cipher
    key:    key, of length 16, 24 or 32
    iv:     initializatoin vector, of length 16 bytes,
            derived from evpBytesToKey
            TODO: use pesudo-random generated IV
    plain:  plain-text, of arbitrary length
    cipher: cipher-text, of arbitrary length

    Note: The boxes process data by block of 128 bits (16 bytes) *)

module AES_Cipher = struct

  type t

  let encryptor ~key ~iv ~plain = 
    let encBox = Cipher.aes ~pad:Padding.length ~iv key Cipher.Encrypt in
    plain >>| fun ptext -> transform_string encBox ptext

  let decrptor ~key ~iv ~cipher =
    let decBox = Cipher.aes ~pad:Padding.length ~iv key Cipher.Decrypt in
    cipher >>| fun ctext -> transform_string decBox ctext
end