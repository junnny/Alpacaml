open Core.Std
open Async.Std
open Core_kernel.Binary_packing

(*

socks proxy, 
tcp server on the client side

*)

module Fd = Unix.Fd
module Inet_addr = Unix.Inet_addr
module Socket = Unix.Socket

let stdout_writer = Lazy.force Writer.stdout
let stderr_writer= Lazy.force Writer.stderr
let message s = Writer.write stdout_writer s
let warn s = Writer.write stderr_writer s

let finished () = shutdown 0

let listening_port = 61115

let remote_host = "127.0.0.1"
let remote_port = 61111

exception Error of string

type args = {
  r : Reader.t;
  w : Writer.t;
};;

type init_req = {
  ver : int;
  nmethods : int;
  methods : int list;
};;

type detail_req = {
  ver : int;
  cmd : int;
  rsv : int;
  atyp : int;
  dst_addr: string;
  dst_port: int;
};;

let password = "nano15532"

let encryptor, decryptor =
  let key, iv = Crypt.evpBytesToKey ~pwd:password ~key_len:32 ~iv_len:16 in
  (Crypt.AES_Cipher.encryptor ~key ~iv, Crypt.AES_Cipher.decryptor ~key ~iv)

(********************** SHARED BY STAGES *********************)
(** not fully deferred *)
(** string -> int -> () *)
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

(** pos should be in range *)
(** string -> int -> int Deferred.t *)
let get_bin req pos =
  let req_len = String.length req in
  if (pos < 0) || (pos >= req_len) then assert false
  else unpack_unsigned_8 ~buf:req ~pos

(********************** STAGE III *********************)


let handle_stage_III buf n local_args remote_args =
  encryptor ~plain:(String.slice buf 3 n) >>=
  (fun enctext ->
     return (Writer.write remote_args.w enctext) >>=
       fun () ->



let stage_III buf n local_args =
  Tcp.with_connection (Tcp.to_host_and_port remote_host remote_port)
  (fun _ r w ->
    let remote_args = 
    {
      r = r;
      w = w;
    } in handle_stage_III buf n local_args remote_args
  )




(********************** STAGE II *********************)
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
        message (Printf.sprintf "%d\n\n" addr_length);
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
    message (Printf.sprintf "VER: %d, CMD: %d, ATYP: %d\n" ver cmd atyp);
    message (Printf.sprintf "ADDR:PORT -> %s : %d\n" dst_addr dst_port);
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
      message (Printf.sprintf "Local connecting: [ %s : %d ]\n" req.dst_addr req.dst_port);
      return (Writer.write local_args.w "\x05\x00\x00\x01\x00\x00\x00\x00\x10\x10") >>=
      (fun () -> stage_III buf n local_args) end
  | _ -> return () (* not supported yet *)

let stage_II buf local_args =
  (Reader.read local_args.r buf) >>= (function
    | `Eof -> message "shit"; return () (*raise (Error "Unexpected EOF\n")*)
    | `Ok n -> parse_stage_II buf n >>= 
                (fun req -> handle_req_stage_II buf n req local_args)
  ) 





(********************** STAGE I *********************)
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
      if validity then 
        (return (Writer.write local_args.w "\x05\x00"))
          >>= (fun () -> stage_II buf local_args)
      else raise (Error "*** Invalid request at STAGE: INIT ***\n")
    ))


(********************** MAIN PART *********************)


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
  message "local side server starts\n";
  Tcp.Server.create (Tcp.on_port listening_port) 
  ~on_handler_error:`Ignore start_listen



let () = server () |> ignore

let () = never_returns (Scheduler.go ())
