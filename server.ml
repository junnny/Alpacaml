open Core.Std
open Async.Std
open Core_kernel.Binary_packing

module Socket = Unix.Socket
module Fd = Unix.Fd
module Inet_addr = Unix.Inet_addr

let stdout_writer = Lazy.force Writer.stdout
let stderr_writer= Lazy.force Writer.stderr
let message s = Writer.write stdout_writer s
let warn s = Writer.write stderr_writer s

let finished () = shutdown 0

let listening_port = 61115

let remote_host = "127.0.0.1"
let remote_port = 61111 

exception Error of string

(** type declaration *)
type args = {
  r : Reader.t;
  w : Writer.t;
};;


type detail_req = {
  atyp : int;
  dst_host: string;
  dst_port: int;
};;


(** Some debugging function *)
let view_request buf n = 
  let poses = List.range 0 n in
  let print_binary p = 
    let bin = unpack_unsigned_8 ~buf ~pos:p in
    message (Printf.sprintf "|%d| " bin)
  in message "Viewing request:\n"; List.iter poses ~f:print_binary;
  message "\nShowing port: ";
  let port = unpack_unsigned_16_big_endian ~buf ~pos:(n - 2) in
  message (Printf.sprintf "%d\n\n" port)

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

(** STAGE II *)

let handle_stage_II buf local_args remote_args =
  let rec transfer local_args remote_args =
    Reader.read local_args.r buf >>= (fun req ->
      | `Eof -> raise (Error "Unexpected EOF\n");
      | `Ok n -> begin
          let plain = decryptor (String.slice buf 0 n) in
          message plain;
          return (Writer.write ~pos:0 ~len:n remote_args.w buf) >>=
            fun () -> 



    )




let stage_II req buf local_args =
  Tcp.with_connection 
  (Tcp.to_host_and_port local_args.dst_host local_args.dst_port)
  (fun _ r w ->
    let remote_args =
    {
      r = r;
      w = w;
    } in handle_stage_II buf local_args remote_args
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
        let dst_port = unpack_unsigned_16_big_endian ~buf ~pos:5 in
        (dst_host, dst_port)
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
        (dst_port, dst_port)
      end
  | _ -> raise (Error "IPV6 is not supported yet\n")

let parse_dst_port req_len req =
  unpack_unsigned_16_big_endian 
  ~buf:req ~pos:(req_len - 2)

let parse_stage_I req =
  Deferred.create (function r ->
    let atyp = get_bin req 0 in
    let dst_host, dst_port = parse_dst_host_and_port atyp req in
    (Printf.sprintf "atyp: %d, dst_host: %s, port : %d" atyp dst_host dst_port) |> message;
    Ivar.fill r
    {
      atyp = atyp;
      dst_host = dst_host;
      dst_port = dst_port;
    }
  )

let stage_I buf n local_args =
  decryptor (String.slice buf 0 n) >>=
  (fun plain -> parse_stage_I plain >>=
    fun req -> stage_II req buf local_args)

let start_listen _ r w =
    let buf = String.create 4096 in
    (Reader.read r buf) >>= (function
      | `Eof -> raise (Error "Unexpected EOF\n")
      | `Ok n -> begin
          let local_args = 
          {
            r = r;
            w = w;
          } in stage_I buf n local_args end)


let server () =
  message "remote side server starts\n";
  Tcp.Server.create (Tcp.on_port remote_port) 
  ~on_handler_error:`Ignore start_listen



let () = server () |> ignore

let () = never_returns (Scheduler.go ())
