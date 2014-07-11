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
open Yojson.Basic.Util

type t = {
  server_addr: string;
  server_port: int;
  local_port: int;
  password: string;
  timeout: int;
  meth: string;
  local_addr: string;
}

let read_config c =
  let open Yojson.Basic.Util in
  let json = Yojson.Basic.from_file c in
  {
    server_addr = json |> member "server" |> to_string;
    server_port = json |> member "server_port" |> to_int;
    local_port = json |> member "local_port" |> to_int;
    password = json |> member "password" |> to_string;
    timeout = json |> member "timeout" |> to_int;
    meth = json |> member "method" |> to_string;
    local_addr = json |> member  "local_address" |> to_string;
  }  