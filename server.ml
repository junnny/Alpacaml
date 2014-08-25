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
open Core_kernel.Binary_packing
open Core_extended.Extended_string

module Socket = Unix.Socket
module Fd = Unix.Fd
module Inet_addr = Unix.Inet_addr

(** hardcoded info *)
let listening_port = 61111

let buf_size = 4096

(** a general exception *)
exception Error of string

(** type declaration *)
type args = {
  r : Reader.t;
  w : Writer.t;
};;


type remote_req = {
  atyp : int;
  dst_host: string;
  dst_port: int;
};;


(** Some debugging function *)


let stdout_writer = Lazy.force Writer.stdout
let stderr_writer= Lazy.force Writer.stderr

let message s = 
  (Printf.sprintf "REMOTE ==> [ %s] : %s\n" 
   (Time.to_filename_string (Time.now ())) s) |> Writer.write stdout_writer

let warn s = 
  (Printf.sprintf "REMOTE ==> [ %s] : %s\n" 
   (Time.to_filename_string (Time.now ())) s) |> Writer.write stderr_writer

let one_byte_message s = Writer.write stdout_writer s

let view_request buf n = 
  let poses = List.range 0 n in
  let print_binary p = 
    let bin = unpack_unsigned_8 ~buf ~pos:p in
    one_byte_message (Printf.sprintf "%c" (char_of_int bin))
  in List.iter poses ~f:print_binary; one_byte_message "\n"

let read_and_review buf args =
  Deferred.create (fun finished ->
    upon (Reader.read args.r buf) (function
      |`Eof -> message "Unexpected EOF\n"; Ivar.fill finished ();
      |`Ok n ->
         message (Printf.sprintf "Read %d bytes this time\n" n);
         view_request buf n;
         Ivar.fill finished ();)
  )


(** turn binary bit from string to int, helper function
    pos should be in range
    string -> int -> int Deferred.t *)
let get_bin req pos =
  let req_len = String.length req in
  if (pos < 0) || (pos >= req_len) then assert false (* should remove in release version *)
  else unpack_unsigned_8 ~buf:req ~pos


(** testing password, AES-256 encryptor and decryptor *)
let password = "nano15532"

let encryptor, decryptor =
  let key, iv = Crypt.evpBytesToKey ~pwd:password ~key_len:32 ~iv_len:16 in
  (Crypt.AES_Cipher.encryptor ~key ~iv, Crypt.AES_Cipher.decryptor ~key ~iv)

(**************************************************************)
let rec handle_remote ~buf ~local_args ~remote_args =
  message "Entering handle_remote\n";
  Reader.read remote_args.r buf >>= function
  | `Eof -> Writer.flushed local_args.w >>= (fun () -> Writer.close local_args.w >>= (fun () -> Writer.close remote_args.w))
  | `Ok n -> begin 
      (message (Printf.sprintf "Receive %d plain bytes from website\n" n));
      (message (Printf.sprintf "View Plain text from website: \n"));
      view_request buf n;
      encryptor ~plain:(String.slice buf 0 n) >>= (fun ctext -> 
        message (Printf.sprintf "%d bytes to write\n" (String.length (String.escaped ctext)));
        Writer.write_line local_args.w (String.escaped ctext);
        Writer.flushed local_args.w >>= (fun () ->
        handle_remote ~buf ~local_args ~remote_args))
      end

let rec handle_local ~local_args ~remote_args =
  message "Entering handle_local\n"; 
  Reader.read_line local_args.r >>= function
  | `Eof -> return ()
  | `Ok encrypted_req -> begin 
      return (unescaped encrypted_req) >>= (fun unes_req ->
      decryptor ~cipher:unes_req >>= (fun ptext ->
        (message (Printf.sprintf "View plain text from remote: \n"));
        view_request ptext (String.length ptext);
        Writer.write remote_args.w ptext;
        Writer.flushed remote_args.w >>= (fun () ->
        handle_local ~local_args ~remote_args)))
      end


(** need to use something similar to "select" *)
let handle_stage_II local_args remote_args =
  message "defer both\n";
  let buf = String.create 4096 in
  (Deferred.both 
  (handle_remote ~buf ~local_args ~remote_args)
  (handle_local ~local_args ~remote_args))
  >>= fun ((), ()) -> return ()


let stage_II req local_args =
  Tcp.with_connection ~timeout:(sec 10000000.)
  (Tcp.to_host_and_port req.dst_host req.dst_port)
  (fun _ r w ->
    let remote_args =
    {
      r = r;
      w = w;
    } in message "remote entering stage II\n"; handle_stage_II local_args remote_args
  )

(** STAGE I, 
    decrypt request from local, 
    parse request,
    further request to STAGE II *)

let parse_dst_host_and_port atyp buf = 
  match () with
  | () when atyp = 1 -> 
      begin
        let host_buf = Bigbuffer.create 20 in
        let rec build_host s e =
          if s = e then Bigbuffer.contents host_buf else 
            (get_bin buf s |> string_of_int |> Bigbuffer.add_string host_buf;
             if s < (e - 1) then Bigbuffer.add_char host_buf '.';
            build_host (s + 1) e)
        in
        let dst_host = build_host 1 5 in
        let dst_port = unpack_unsigned_16_big_endian ~buf ~pos:5
        in (dst_host, dst_port)
      end
  | () when atyp = 3 ->
      begin 
        let host_length = get_bin buf 1 in
        let host_buf = Bigbuffer.create host_length in
        let rec build_host s e =
          if s = e then Bigbuffer.contents host_buf else
            (get_bin buf s |> char_of_int |> Bigbuffer.add_char host_buf;
            build_host (s + 1) e)
        in 
        let dst_host = build_host 2 (2 + host_length) in
        let dst_port = unpack_unsigned_16_big_endian ~buf ~pos:(2 + host_length) in
        (dst_host, dst_port)
      end
  | _ -> raise (Error "IPV6 is not supported yet\n")

let parse_dst_port req_len req =
  unpack_unsigned_16_big_endian 
  ~buf:req ~pos:(req_len - 2)

let parse_stage_I req =
  Deferred.create (function r ->
    let atyp = get_bin req 0 in
    let dst_host, dst_port = parse_dst_host_and_port atyp req in
    (Printf.sprintf "atyp: %d, dst_host: %s, port : %d\n" atyp dst_host dst_port) |> message;
    (Printf.sprintf "request length!!!!: %d\n" (String.length req)) |> message;
    Ivar.fill r
    {
      atyp = atyp;
      dst_host = dst_host;
      dst_port = dst_port;
    }
  )

let stage_I req local_args =
  return (unescaped req) >>= (fun unes_req -> decryptor ~cipher:unes_req >>=
  (fun plain -> 
    message (Printf.sprintf "STAGE_I receive local request, view now\n");
    parse_stage_I plain >>=
    fun req -> stage_II req local_args))

let start_listen _ r w =
    message "\n******************************* NEW CONNECTION ******************************\n";
    (Reader.read_line r) >>= (function
      | `Eof -> raise (Error "Unexpected EOF\n")
      | `Ok req ->
          let local_args = 
          {
            r = r;
            w = w;
          } in stage_I req local_args
    )


let server () =
  message "remote side server starts\n";
  Tcp.Server.create (Tcp.on_port listening_port) 
  ~on_handler_error:`Ignore start_listen



let () = server () |> ignore

let () = never_returns (Scheduler.go ())
