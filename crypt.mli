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


(** auxiliary function, decode hex *)
val hex : s:string -> string = <fun> 

(** auxiliary function, encode to hex *)
val tohex : s:string -> string = <fun>

(** derive 32-byte key from string of arbitrary size *)
val deriveSha256 : s:string -> string = <fun> 

(** derive 16-byte key from string of arbitrary size *)
val deriveMd5 : s:string -> string = <fun>

(** similar to OpenSSL's EVP_BytesToKey() *)
val evpBytesToKey : pwd:string -> key_len:int -> iv_len:int -> string * string = <fun>

(** AES cipher module *)
module AES_Cipher : sig
  type t
    
  val encryptor : key:string -> iv:string -> plain:string Deferred.t -> string Deferred.t
    
  val decrptor : key:string -> iv:string -> cipher:string Deferred.t -> string Deferred.t
end