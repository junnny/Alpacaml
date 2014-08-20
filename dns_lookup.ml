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

let host = ["www.gutenberg.org/cache/epub/2600/pg2600.txt"; "www.bilibili.tv"; "www.zhihu.com"]

let rec dns_lookup domains =
  match domains with
  | [] -> print_endline "Finished"; exit 0
  | x :: res -> 
     Unix.Inet_addr.of_string_or_getbyname x >>=
     (fun addr -> 
        printf "%s: " x; Unix.Inet_addr.to_string addr |> print_endline;
        dns_lookup res)


let () = don't_wait_for (dns_lookup host)

let () = never_returns (Scheduler.go ())
