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

(** hardcoded info *)
let listening_port = 61111

let send_buf_size = 4096
let recv_buf_size = 4200

let header_len = 16

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
;;

let warn s = 
  (Printf.sprintf "REMOTE ==> [ %s] : %s\n" 
   (Time.to_filename_string (Time.now ())) s) |> Writer.write stderr_writer
;;

let one_byte_message s = Writer.write stdout_writer s

let view_request buf n = 
  let poses = List.range 0 n in
  let print_binary p = 
    let bin = unpack_unsigned_8 ~buf ~pos:p in
    one_byte_message (Printf.sprintf "%c" (char_of_int bin))
  in List.iter poses ~f:print_binary; one_byte_message "\n"
;;

let read_and_review buf args =
  Deferred.create (fun finished ->
    upon (Reader.read args.r buf) (function
      |`Eof -> message "Unexpected EOF\n"; Ivar.fill finished ();
      |`Ok n ->
         begin
         message (Printf.sprintf "Read %d bytes this time\n" n);
         view_request buf n;
         Ivar.fill finished ()
         end)
  )
;;


(** turn binary bit from string to int, helper function
    pos should be in range
    string -> int -> int Deferred.t *)
let get_bin req pos = unpack_unsigned_8 ~buf:req ~pos

(** testing password, AES-256 encryptor and decryptor *)
let password = "nano15532"

let encryptor, decryptor =
  let key, iv = Crypt.evpBytesToKey ~pwd:password ~key_len:32 ~iv_len:16 in
  (Crypt.AES_Cipher.encryptor ~key ~iv, Crypt.AES_Cipher.decryptor ~key ~iv)
;;

(**************************************************************)
let rec handle_remote ~buf ~local_args ~remote_args =
  Reader.read remote_args.r buf >>= 
  (function
    | `Eof -> Writer.close local_args.w >>= (fun () -> 
                Reader.close remote_args.r)
    | `Ok n ->
        encryptor ~ptext:(String.slice buf 0 n) >>= (fun enc_text ->
          encryptor ~ptext:(string_of_int (String.length enc_text)) >>= (fun enc_len ->
            Writer.write local_args.w enc_len;
            Writer.write local_args.w enc_text;
            handle_remote ~buf ~local_args ~remote_args))
  )
;;

let rec handle_local ~buf ~local_args ~remote_args =
  Reader.really_read local_args.r ~pos:0 ~len:header_len buf >>= 
  (function
    | `Eof _ -> return () (*raise (Error "Local closed unexpectedly\n");*)
    | `Ok -> 
        begin
        decryptor ~ctext:(String.slice buf 0 header_len) >>= (fun req_len ->
          let req_len = int_of_string req_len in
          Reader.really_read local_args.r ~pos:0 ~len:req_len buf >>= 
          (function
            | `Eof _ -> raise (Error "Local closed unexpectedly\n");
            | `Ok -> 
                decryptor 
                ~ctext:(String.slice buf 0 req_len) >>= (fun raw_req ->
                  Writer.write remote_args.w raw_req;
                  handle_local ~buf ~local_args ~remote_args)
          )) 
        end
  )
;;

(** need to use something similar to "select" *)
let handle_stage_II buf_local local_args remote_args =
  let buf_remote = String.create send_buf_size in
  (Deferred.both 
  (handle_remote ~buf:buf_remote ~local_args ~remote_args)
  (handle_local ~buf:buf_local ~local_args ~remote_args))
  >>= fun ((), ()) -> return ()
;;


let stage_II buf req local_args =
  Tcp.with_connection
  (Tcp.to_host_and_port req.dst_host req.dst_port)
  (fun _ r w ->
    let remote_args =
    {
      r = r;
      w = w;
    } in
    handle_stage_II buf local_args remote_args
  )
;;

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
;;

let parse_dst_port req_len req =
  unpack_unsigned_16_big_endian ~buf:req ~pos:(req_len - 2)

let parse_stage_I req =
  Deferred.create (function r ->
    let atyp = get_bin req 0 in
    let dst_host, dst_port = parse_dst_host_and_port atyp req in
    Ivar.fill r
    {
      atyp = atyp;
      dst_host = dst_host;
      dst_port = dst_port;
    }
  )
;;

let stage_I buf req_len local_args =
  Reader.really_read local_args.r ~pos:0 ~len:req_len buf >>=
  (function
    | `Eof _ -> raise (Error "Local closed unexpectedly")
    | `Ok -> decryptor ~ctext:(String.slice buf 0 req_len) >>= (fun raw_req ->
               parse_stage_I raw_req >>= (fun req ->
                 stage_II buf req local_args))
  )
;;

let start_listen _ r w =
  let buf = String.create recv_buf_size in
  (Reader.really_read r ~pos:0 ~len:header_len buf) >>= 
  (function
    | `Eof _ -> raise (Error "Local closed unexpectedly")
    | `Ok -> decryptor ~ctext:(String.slice buf 0 header_len) >>=
        (fun req_len -> 
          let local_args =
          {
            r = r;
            w = w;
          } in stage_I buf (int_of_string req_len) local_args)
  )
;;

let server () =
  Tcp.Server.create (Tcp.on_port listening_port) 
  ~on_handler_error:`Ignore start_listen
;;

let () = ignore (server ())

let () = never_returns (Scheduler.go ())
