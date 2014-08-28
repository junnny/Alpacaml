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

(** auxiliary function, decode from hex *)
val hex : s:string -> string

(** auxiliary function, encode to hex *)
val tohex : s:string -> string

(** derive 32-byte key from string of arbitrary size *)
val deriveSha256 : s:string -> string

(** derive 16-byte key from string of arbitrary size *)
val deriveMd5 : s:string -> string

(** implementation of OpenSSL's EVP_BytesToKey() *)
val evpBytesToKey : pwd:string -> key_len:int -> iv_len:int -> (string * string)

(** a pseudo-random number generator using seed provided by
    a high-quality random number generator.
    Note: this implementation is suggested in Xavier Leroy's cryptokit.
*)
val prng : unit -> Random.rng

(** AES cipher, support AES-128-
    key:    key, of length 16, 24 or 32
    iv:     initializatoin vector, of length 16 bytes,
            derived from evpBytesToKey
    plain:  plain-text, of arbitrary length
    cipher: cipher-text, of arbitrary length

    Note: 
    1. The boxes process data by block of 128 bits (16 bytes)*)
  
module AES_Cipher : sig

  val encryptor : key:string -> iv:string -> ptext:string -> string Deferred.t
    
  val decryptor : key:string -> iv:string -> ctext:string -> string Deferred.t
end

(** Same AES cipher but with random generated IV every encryption *)
module AES_256_CBC_RandomIV : sig

  val encryptor: key:string -> prng:Random.rng -> ptext:string ->
                 string Deferred.t

  val decryptor: key:string -> iv:string -> ctext:string -> string Deferred.t
end

open Sodium

module Libsodium : sig
  val get_nonce : unit -> Box.nonce Deferred.t
    
  val gen_sk_pk : unit -> Box.keypair Deferred.t
    
  val encryptor : sk:secret Box.key -> pk':public Box.key -> ptext:string -> 
                    nonce:Box.nonce -> string Deferred.t
    
  val decryptor : sk:secret Box.key -> pk':public Box.key -> ctext:string -> 
                    nonce:Box.nonce -> string Deferred.t
    
  val sk_to_storage : sk:secret Box.key -> string Deferred.t
    
  val pk_to_storage : pk:public Box.key -> string Deferred.t
    
  val nonce_to_storage : nonce:Box.nonce -> string Deferred.t
    
  val storage_to_sk : storage:string -> secret Box.key Deferred.t
    
  val storage_to_pk : storage:string -> public Box.key Deferred.t
    
  val stoarge_to_nonce : storage:string -> Box.nonce Deferred.t
    
  val compute_channel_key : sk:secret Box.key -> pk':public Box.key -> 
                              channel Box.key Deferred.t
    
  val fast_encryptor : ck:channel Box.key -> ptext:string -> 
                         nonce:Box.nonce -> string Deferred.t
    
  val fast_decryptor : ck:channel Box.key -> ctext:string -> 
                         nonce:Box.nonce -> string Deferred.t
end
