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


val listening_port : int

exception Error of string
exception Unexpected_EOF


type arguments
type 'a buf
type 'a args

type remote_req

type local
type remote

type l_buf
type r_buf

type l_args
type r_args

val stdout_writer : Async_unix.Writer.t

val stderr_writer : Async_unix.Writer.t

val message : string -> unit

val warn : string -> unit

val one_byte_message : string -> unit

val view_request : string -> int -> unit

val read_and_review : string -> arguments -> unit Async_kernel.Deferred.t

module type REMOTE_TRANSFER = sig
  val local_buf_size : int
  val remote_buf_size : int
  val start_listen :
    'a ->
    Async_unix.Reader.t ->
    Async_unix.Writer.t -> unit Async_kernel.Deferred.t
  val init_and_nego :
    l_buf -> int -> l_args -> unit Async_kernel.Deferred.t
  val data_transfer :
    l_buf:l_buf ->
    r_buf:r_buf ->
    l_args:l_args -> r_args:r_args -> unit Async_kernel.Deferred.t
end

module Parse_request : sig
  val get_bin : string -> int -> int
  val parse_dst_host_and_port : int -> string -> string * int
  val parse_dst_port : int -> string -> int
  val parse_init_req : string -> remote_req Async_kernel.Deferred.t
end

module AES_256_CBC : REMOTE_TRANSFER

val server :
  unit ->
  (Async_extra.Import.Socket.Address.Inet.t, int) Async_extra.Tcp.Server.t
  Async_kernel.Deferred.t
