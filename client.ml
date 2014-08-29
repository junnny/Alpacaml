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
let listening_port = 61115
let remote_host = "127.0.0.1"
let remote_port = 61111

(** general exceptions *)
exception Error of string
exception Unexpected_EOF

(** type declaration *)
type arguments = {
  r : Reader.t;
  w : Writer.t;
}

type local_init_req = {
  ver : int;
  nmethods : int;
  methods : int list;
}

type local_detail_req = {
  ver : int;
  cmd : int;
  rsv : int;
  atyp : int;
  dst_addr: string;
  dst_port: int;
}

type 'a buf = string
type 'a args = arguments

type local
type remote

type l_buf = local buf
type r_buf = remote buf

type l_args = local args
type r_args = remote args

module type STAGE_I = sig
  
  val start_listen : 'a -> Reader.t -> Writer.t -> unit Deferred.t

  val init_and_nego :
    l_buf
    -> int 
    -> l_args
    -> unit Deferred.t
end

module type STAGE_II = sig
  
  val l_buf_size : int
  val r_buf_size : int

  val remote_init : 
    l_buf
    -> int
    -> l_args
    -> unit Deferred.t
 
  val data_transfer : 
    l_buf:l_buf
    -> r_buf:r_buf
    -> l_args:l_args
    -> r_args:r_args
    -> unit Deferred.t

end

module type LOCAL_TRANSFER = sig
  
  include STAGE_I
  include STAGE_II

end

(** Some debugging functions *)
let stdout_writer () = Lazy.force Writer.stdout
let stderr_writer () = Lazy.force Writer.stderr

let message s =
  (Printf.sprintf "LOCAL ==> [ %s] : %s\n" 
   (Time.to_filename_string (Time.now ())) s) |> Writer.write (stdout_writer ())
;;

let warn s = 
  (Printf.sprintf "LOCAL ==> [ %s] : %s\n" 
   (Time.to_filename_string (Time.now ())) s) |> Writer.write (stderr_writer ())
;;

let one_byte_message s = Writer.write (stdout_writer ()) s

(** not fully deferred *)
let view_request buf n = 
  let poses = List.range 0 n in
  let print_binary p = 
    let bin = unpack_unsigned_8 ~buf ~pos:p in
    one_byte_message (Printf.sprintf "%c" (char_of_int bin))
  in List.iter poses ~f:print_binary; one_byte_message "\n"
;;

let read_and_review buf args =
  Deferred.create (fun finished ->
    upon (Reader.read args.r buf) 
    (function
      | `Eof -> message "Unexpected EOF\n"; Ivar.fill finished ();
      | `Ok n ->
         message (Printf.sprintf "Read %d bytes this time\n" n);
         view_request buf n;
         Ivar.fill finished ();
    )
  )
;;

module Parse_request = struct

  let get_bin req pos = unpack_unsigned_8 ~buf:req ~pos

  let parse_init_req req req_len =
    return
    {
      ver = get_bin req 0;
      nmethods = get_bin req 1;
      methods = List.range 2 req_len |> List.map ~f:(get_bin req);
    }
  ;;

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
  ;;
  
  
  let parse_dst_port req_len req =
    unpack_unsigned_16_big_endian ~buf:req ~pos:(req_len - 2)
  ;;
  
  let parse_detail_req req req_len =
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
  ;;

end

module Local_transfer (Stage_II: STAGE_II) : LOCAL_TRANSFER = struct
  
  include Parse_request

  let remote_init = Stage_II.remote_init
  let data_transfer = Stage_II.data_transfer
  
  let l_buf_size = Stage_II.l_buf_size
  let r_buf_size = Stage_II.r_buf_size

  let gen_l_buf () = 
    return (String.create l_buf_size)

  let init_and_nego buf n l_args =
    parse_init_req buf n >>= (fun init_req ->
      return (
        init_req.ver = 5 &&
        init_req.nmethods > 0 &&
        List.exists init_req.methods ~f:(fun x -> x = 0)
      ) >>=
      (fun valid ->
        if not valid then 
          Writer.close l_args.w >>= (fun () -> raise (Error "Invalid request"))
        else begin
        Writer.write l_args.w "\x05\x00";
        Reader.read l_args.r buf >>= (function
         | `Eof -> Writer.close l_args.w >>= (fun () -> raise Unexpected_EOF)
         | `Ok n -> 
             parse_detail_req buf n >>= (fun req ->
              match () with
              | () when req.cmd = 1 -> 
                 begin
                   let reply = "\x05\x00\x00\x01\x00\x00\x00\x00\x10\x10" in
                   let log_msg =
                      Printf.sprintf "Connecting: [%s: %d]\n"
                      req.dst_addr 
                      req.dst_port 
                   in 
                   message log_msg;
                   Writer.write l_args.w reply; 
                   remote_init buf n l_args
                 end
              | _ -> 
                 let exp_msg = 
                 (Printf.sprintf "Unsupported command type: %d\n" req.cmd) in
                 Writer.close l_args.w >>= (fun () -> raise (Error exp_msg))
             )
        )
        end
      )
    )
  ;;

  let start_listen _ r w =
    gen_l_buf () >>= (fun buf ->
    (Reader.read r buf) >>= (function
      | `Eof -> Writer.close w >>= (fun () -> raise Unexpected_EOF)
      | `Ok n -> begin
           let l_args = { r = r; w = w;}
           in init_and_nego buf n l_args
         end
    ))
  ;;

end

module AES_256_CBC : STAGE_II = struct
  
  let l_buf_size = 4096
  let r_buf_size = 4200
  let password = "nano15532"

  let header_len = 16

  let gen_r_buf () = 
    return (String.create r_buf_size)

  let encryptor, decryptor =
    let key, iv = Crypt.evpBytesToKey ~pwd:password ~key_len:32 ~iv_len:16 in
    (Crypt.AES_Cipher.encryptor ~key ~iv, Crypt.AES_Cipher.decryptor ~key ~iv)
  ;;

  let rec handle_remote (buf:r_buf) (l_args:l_args) (r_args:r_args) =
    Reader.really_read r_args.r ~pos:0 ~len:header_len buf >>=
    (function 
      | `Eof _ -> Writer.close l_args.w >>= (fun () ->
                    Reader.close r_args.r)
      | `Ok ->
          begin
          decryptor ~ctext:(String.slice buf 0 header_len) >>= (fun req_len ->
            let req_len = int_of_string req_len in
            Reader.really_read r_args.r ~pos:0 ~len:req_len buf >>=
            (function
              | `Eof _ -> raise (Error "Local closed unexpectedly\n");
              | `Ok ->
                  decryptor 
                  ~ctext:(String.slice buf 0 req_len) >>= (fun raw_data ->
                    Writer.write l_args.w raw_data;
                    handle_remote buf l_args r_args)))
          end
    )
  ;;
  
  let rec handle_local (buf:l_buf) (l_args:l_args) (r_args:r_args) =
    Reader.read l_args.r buf >>= 
    (function
      | `Eof -> return ()
      | `Ok n ->
          encryptor ~ptext:(String.slice buf 0 n) >>= (fun enc_text ->
            encryptor ~ptext:(string_of_int (String.length enc_text)) >>= 
            (fun enc_len ->
              Writer.write r_args.w enc_len;
              Writer.write r_args.w enc_text;
              handle_local buf l_args r_args)))
  ;;

  let data_transfer ~l_buf ~r_buf ~l_args ~r_args =
    (Deferred.both 
    (handle_remote r_buf l_args r_args)
    (handle_local l_buf l_args r_args))
    >>= fun ((), ()) -> return ()
  ;;

  let send_addr_info buf n ~l_args ~r_args = 
    encryptor ~ptext:(String.slice buf 3 n) >>= (fun enc_text ->
      encryptor ~ptext:(string_of_int (String.length enc_text)) >>= 
      (fun enc_len ->
        Writer.write r_args.w enc_len;
        Writer.write r_args.w enc_text;
        gen_r_buf () >>= (fun r_buf ->
          data_transfer ~l_buf:buf ~r_buf ~l_args ~r_args)
      )
    )
  ;;

  let remote_init buf n l_args =
    Tcp.with_connection (Tcp.to_host_and_port remote_host remote_port)
    (fun _ r w ->
      let r_args = {r = r; w = w;}
      in send_addr_info buf n ~l_args ~r_args)
  ;;

end

let server () =
  let module Handler = Local_transfer(AES_256_CBC) in
  Tcp.Server.create (Tcp.on_port listening_port) 
  ~on_handler_error:`Ignore Handler.start_listen
;;


let () = never_returns 
  (Scheduler.go_main ~max_num_open_file_descrs:32768 ~max_num_threads:4096 
    ~main:(fun () -> ignore (server ())) ())
