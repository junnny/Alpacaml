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



(** a general exception *)
exception Error of string
;;

exception Unexpected_EOF
;;


(** type declaration *)
type arguments = {
  r : Reader.t;
  w : Writer.t;
};;


type remote_req = {
  atyp : int;
  dst_host: string;
  dst_port: int;
};;

type 'a buf = string
type 'a args = arguments

type local
type remote

type l_buf = local buf
type r_buf = remote buf

type l_args = local args
type r_args = remote args




(** Some debugging function *)
let stdout_writer = Lazy.force Writer.stdout
let stderr_writer = Lazy.force Writer.stderr

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


module type REMOTE_TRANSFER = sig

  val local_buf_size : int
  val remote_buf_size : int

  val start_listen : 'a -> Reader.t -> Writer.t -> unit Deferred.t

  val init_and_nego : 
    l_buf
    -> int
    -> l_args
    -> unit Deferred.t
  
  val data_transfer :
    l_buf: l_buf
    -> r_buf: r_buf
    -> l_args: l_args
    -> r_args: r_args
    -> unit Deferred.t

end


module Parse_request = struct
  
  let get_bin req pos = unpack_unsigned_8 ~buf:req ~pos

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
  
  let parse_init_req req =
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
  
end

module AES_CFB : REMOTE_TRANSFER = struct

  include Parse_request

  let local_buf_size = 4200
  
  let remote_buf_size = 4096

  let header_len = 16

  let gen_local_buf () = 
    return (String.create local_buf_size)

  let gen_remote_buf () = 
    return (String.create remote_buf_size)

  (** testing password, AES-256 encryptor and decryptor *)
  let password = "nano15532"
  
  let encryptor, decryptor =
    let key, iv = Crypt.evpBytesToKey ~pwd:password ~key_len:32 ~iv_len:16 in
    (Crypt.AES_Cipher.encryptor ~key ~iv, Crypt.AES_Cipher.decryptor ~key ~iv)
  ;;
  
  (**************************************************************)
  let rec handle_remote (buf:r_buf) (l_args:l_args) (r_args:r_args) =
    Reader.read r_args.r buf >>= 
    (function
      | `Eof -> Writer.close l_args.w >>= (fun () -> 
                  Reader.close r_args.r)
      | `Ok n ->
          encryptor ~ptext:(String.slice buf 0 n) >>= (fun enc_text ->
            encryptor ~ptext:(string_of_int (String.length enc_text)) >>= (fun enc_len ->
              Writer.write l_args.w enc_len;
              Writer.write l_args.w enc_text;
              handle_remote buf l_args r_args))
    )
  ;;
  
  let rec handle_local (buf:l_buf) (l_args:l_args) (r_args:r_args) =
    Reader.really_read l_args.r ~pos:0 ~len:header_len buf >>= 
    (function
      | `Eof _ -> return ()
      | `Ok -> 
          begin
          decryptor ~ctext:(String.slice buf 0 header_len) >>= (fun req_len ->
            let req_len = int_of_string req_len in
            Reader.really_read l_args.r ~pos:0 ~len:req_len buf >>= 
            (function
              | `Eof _ -> raise (Error "Local closed unexpectedly\n");
              | `Ok -> 
                  decryptor 
                  ~ctext:(String.slice buf 0 req_len) >>= (fun raw_req ->
                    Writer.write r_args.w raw_req;
                    handle_local buf l_args r_args)
            )) 
          end
    )
  ;;
  
  (** need to use something similar to "select" *)
  let data_transfer ~l_buf ~r_buf ~l_args ~r_args =
    (Deferred.both 
    (handle_remote r_buf l_args r_args)
    (handle_local l_buf l_args r_args))
    >>= fun ((), ()) -> return ()
  ;;
  
  
  let init_and_nego buf req_len l_args =
    Reader.really_read l_args.r ~pos:0 ~len:req_len buf >>=
    (function
      | `Eof _ -> raise Unexpected_EOF
      | `Ok -> 
          decryptor ~ctext:(String.slice buf 0 req_len) >>= (fun raw_req ->
            parse_init_req raw_req >>= (fun req ->
              Tcp.with_connection 
              (Tcp.to_host_and_port req.dst_host req.dst_port)
              (fun _ r w ->
                let r_args : r_args = {r = r; w = w} in 
                gen_remote_buf () >>= (fun r_buf ->
                  data_transfer ~l_buf:buf ~r_buf ~l_args ~r_args)
              )))
    )
  ;;
  
  let start_listen _ r w =
    gen_local_buf () >>= (fun buf ->
    (Reader.really_read r ~pos:0 ~len:header_len buf) >>= 
    (function
      | `Eof _ -> raise (Error "Local closed unexpectedly")
      | `Ok -> decryptor ~ctext:(String.slice buf 0 header_len) >>=
          (fun req_len -> 
            let l_args : l_args = {r = r; w = w;}
            in init_and_nego buf (int_of_string req_len) l_args)
    ))
  ;;

end

let server () =
  let module Handler = AES_CFB in
  Tcp.Server.create (Tcp.on_port listening_port) 
  ~on_handler_error:`Ignore Handler.start_listen
;;

let () = ignore (server ())

let () = never_returns (Scheduler.go ())
