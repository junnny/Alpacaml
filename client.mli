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

val remote_host : string

val remote_port : int

exception Error of string

exception Unexpected_EOF

type local_init_req

type local_detail_req

type local

type remote

type l_buf 

type r_buf

type l_args

type r_args

module type STAGE_I = sig
  val start_listen :
    'a ->
    Async_unix.Reader.t ->
    Async_unix.Writer.t -> unit Async_kernel.Deferred.t
  val init_and_nego :
    local_buf -> int -> l_args -> unit Async_kernel.Deferred.t
end

module type STAGE_II = sig
  val local_buf_size : int
  val remote_buf_size : int
  val remote_init :
    local_buf -> int -> l_args -> unit Async_kernel.Deferred.t
  val data_transfer :
    l_buf:local_buf ->
    r_buf:remote_buf ->
    l_args:l_args -> r_args:r_args -> unit Async_kernel.Deferred.t
end

module type LOCAL_TRANSFER = sig
  val start_listen :
    'a ->
    Async_unix.Reader.t ->
    Async_unix.Writer.t -> unit Async_kernel.Deferred.t
  val init_and_nego :
    local_buf -> int -> l_args -> unit Async_kernel.Deferred.t
  val local_buf_size : int
  val remote_buf_size : int
  val remote_init :
    local_buf -> int -> l_args -> unit Async_kernel.Deferred.t
  val data_transfer :
    l_buf:local_buf ->
    r_buf:remote_buf ->
    l_args:l_args -> r_args:r_args -> unit Async_kernel.Deferred.t
end

val stdout_writer : Async_unix.Writer.t

val stderr_writer : Async_unix.Writer.t

val message : string -> unit

val warn : string -> unit

val one_byte_message : string -> unit

val view_request : string -> int -> unit

val read_and_review : string -> arguments -> unit Async_kernel.Deferred.t

module Parse_request : sig
  val get_bin : string -> int -> int
  val parse_init_req :
    string -> int -> local_init_req Async_kernel.Deferred.t
  val parse_dst_addr : int -> string -> string
  val parse_dst_port : int -> string -> int
  val parse_detail_req :
    string -> int -> local_detail_req Async_kernel.Deferred.t
end

module Local_transfer : functor (Stage_II : STAGE_II) -> LOCAL_TRANSFER

module AES_CBC : STAGE_II

val server :
  unit ->
  (Async_extra.Import.Socket.Address.Inet.t, int) Async_extra.Tcp.Server.t
  Async_kernel.Deferred.t

