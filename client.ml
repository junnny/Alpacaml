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

module Fd = Unix.Fd
module Inet_addr = Unix.Inet_addr
module Socket = Unix.Socket

(** hardcoded info *)
let listening_port = 61115

let remote_host = "127.0.0.1"
let remote_port = 61111

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

type local_init_req = {
  ver : int;
  nmethods : int;
  methods : int list;
};;

type local_detail_req = {
  ver : int;
  cmd : int;
  rsv : int;
  atyp : int;
  dst_addr: string;
  dst_port: int;
};;

(** Some debugging functions *)

let stdout_writer = Lazy.force Writer.stdout
let stderr_writer = Lazy.force Writer.stderr
let message s =
  (Printf.sprintf "LOCAL ==> [ %s] : %s\n" 
   (Time.to_filename_string (Time.now ())) s) |> Writer.write stdout_writer 

let warn s = 
  (Printf.sprintf "LOCAL ==> [ %s] : %s\n" 
   (Time.to_filename_string (Time.now ())) s) |> Writer.write stderr_writer

let one_byte_message s = Writer.write stdout_writer s

(** not fully deferred *)
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
  if (pos < 0) || (pos >= req_len) then assert false
  else unpack_unsigned_8 ~buf:req ~pos



(** testing password, AES-256 encryptor and decryptor *)
let password = "nano15532"

let encryptor, decryptor =
  let key, iv = Crypt.evpBytesToKey ~pwd:password ~key_len:32 ~iv_len:16 in
  (Crypt.AES_Cipher.encryptor ~key ~iv, Crypt.AES_Cipher.decryptor ~key ~iv)

let af_enc_len n =
  let mo = (n % 16) in
  if mo = 0 then n else (16 - mo + n)
;;

(** STAGE IV *)

let rec handle_remote ~buf ~local_args ~remote_args =
  Reader.really_read remote_args.r ~pos:0 ~len:header_len buf >>=
  (function 
    | `Eof _ -> Writer.close local_args.w >>= (fun () ->
                  Reader.close remote_args.r)
    | `Ok ->
        begin
        decryptor ~ctext:(String.slice buf 0 header_len) >>= (fun req_len ->
          let req_len = int_of_string req_len in
          message (Printf.sprintf "TO RECEIVE length %d\n" req_len);
          Reader.really_read remote_args.r ~pos:0 ~len:req_len buf >>=
          (function
            | `Eof _ -> raise (Error "Local closed unexpectedly\n");
            | `Ok ->
                decryptor 
                ~ctext:(String.slice buf 0 req_len) >>= (fun raw_data ->
                  Writer.write local_args.w raw_data;
                  handle_remote ~buf ~local_args ~remote_args)
          ))
        end
  )

let rec handle_local ~buf ~local_args ~remote_args =
  Reader.read local_args.r buf >>= 
  (function
    | `Eof -> return ()
    | `Ok n ->
        encryptor ~ptext:(String.slice buf 0 n) >>= (fun enc_text ->
          encryptor ~ptext:(string_of_int (String.length enc_text)) >>= (fun enc_len ->
            message (Printf.sprintf "plain text length : %d\n" n);
            message (Printf.sprintf "encrypted text length : %d\n" (String.length enc_text));
            Writer.write remote_args.w enc_len;
            Writer.write remote_args.w enc_text;
            handle_local ~buf ~local_args ~remote_args))
  )

(** need to use something similar to "select" *)
let stage_IV buf_local local_args remote_args =
  let buf_remote = String.create recv_buf_size in
  (Deferred.both 
  (handle_remote ~buf:buf_remote~local_args ~remote_args)
  (handle_local ~buf:buf_local ~local_args ~remote_args))
  >>= fun ((), ()) -> return ()


(********************** STAGE III *********************)

(** need to use something similar to "select" *)
let handle_stage_III buf n local_args remote_args =
  encryptor ~ptext:(String.slice buf 3 n) >>= (fun enc_text ->
    encryptor ~ptext:(string_of_int (String.length enc_text)) >>= (fun enc_len ->
      Writer.write remote_args.w enc_len;
      view_request buf n;
      message (Printf.sprintf "plain text length : %d\n" (n - 3));
      message (Printf.sprintf "encrypted text length : %d\n" (String.length enc_text));
      Writer.write remote_args.w enc_text;
      stage_IV buf local_args remote_args
    )
  ) 

let stage_III buf n local_args =
  Tcp.with_connection (Tcp.to_host_and_port remote_host remote_port)
  (fun _ r w ->
    let remote_args = 
    {
      r = r;
      w = w;
    } in handle_stage_III buf n local_args remote_args
  )

(** STAGE II *)

let parse_dst_addr atyp buf = 
  match () with
  | () when atyp = 1 -> 
      begin
        let addr_buf = Bigbuffer.create 16 in
        let rec build_addr s e =
          if s = e then Bigbuffer.contents addr_buf else 
            (get_bin buf s |> string_of_int |> Bigbuffer.add_string addr_buf;
             if s < (e - 1) then Bigbuffer.add_char addr_buf '.';
            build_addr (s + 1) e)
        in build_addr 4 8
      end
  | () when atyp = 3 ->
      begin 
        let addr_length = get_bin buf 4 in
        let addr_buf = Bigbuffer.create addr_length in
        let rec build_addr s e =
          if s = e then Bigbuffer.contents addr_buf else
            (get_bin buf s |> char_of_int |> Bigbuffer.add_char addr_buf;
            build_addr (s + 1) e)
          in build_addr 5 (5 + addr_length)
      end
  | _ -> raise (Error "Address type not supported yet\n")


let parse_dst_port req_len req =
  unpack_unsigned_16_big_endian ~buf:req ~pos:(req_len - 2)

let parse_stage_II req req_len =
  Deferred.create (function r ->
    let ver = get_bin req 0
    and cmd = get_bin req 1
    and rsv = get_bin req 2
    and atyp = get_bin req 3 in
    let dst_addr = parse_dst_addr atyp req in
    let dst_port = parse_dst_port req_len req in
    Ivar.fill r
    {
      ver = ver;
      cmd = cmd;
      rsv = rsv;
      atyp = atyp;
      dst_addr = dst_addr;
      dst_port = dst_port;
    }
  )

let handle_req_stage_II buf n req local_args =
  match () with
  | () when req.cmd = 1 -> begin
      message 
      (Printf.sprintf "Local connecting: [ %s : %d ]\n" 
       req.dst_addr req.dst_port);
      Writer.write local_args.w "\x05\x00\x00\x01\x00\x00\x00\x00\x10\x10";
      stage_III buf n local_args
      end
  | _ -> warn (Printf.sprintf "CMD TYPE UNSUPPORTED : %d\n" req.cmd); return () 
         (* not supported yet *)

let stage_II buf local_args =
  (Reader.read local_args.r buf) >>= (function
    | `Eof -> warn "Client ends connection unexpectedly\n"; return () (*raise (Error "Unexpected EOF\n")*)
    | `Ok n -> parse_stage_II buf n >>= 
                (fun req -> handle_req_stage_II buf n req local_args)
  ) 


(** STAGE I *)

(** string -> init_req Deferred.t *)
let parse_stage_I req req_len = 
  return 
  {
    ver = get_bin req 0;
    nmethods = get_bin req 1;
    methods = List.range 2 req_len |> List.map ~f:(get_bin req);
  }

let stage_I buf n local_args = 
  parse_stage_I buf n >>= (fun init_req ->
    return (
      init_req.ver = 5 && 
      init_req.nmethods > 0 && 
      List.exists init_req.methods ~f:(fun x -> x = 0)
    ) >>= 
    (fun validity ->
      if validity then begin
        Writer.write local_args.w "\x05\x00";
        stage_II buf local_args 
      end
      else raise (Error "*** Invalid request at STAGE: INIT ***\n")
    ))


(********************** MAIN PART *********************)

let start_listen _ r w =
    message "\n******************************* NEW CONNECTION ******************************\n";
    let buf = String.create send_buf_size in
    (Reader.read r buf) >>= (function
      | `Eof -> raise (Error "Unexpected EOF\n")
      | `Ok n -> begin
          let local_args = 
          {
            r = r;
            w = w;
          } in stage_I buf n local_args end)

let server () =
  message "local side server starts\n";
  Tcp.Server.create (Tcp.on_port listening_port) 
  ~on_handler_error:`Ignore start_listen

let () = server () |> ignore

let () = never_returns (Scheduler.go ())
