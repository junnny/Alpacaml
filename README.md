Alpacaml
========
Alpacaml is a type-safe, Monadic, fully asynchronous and encrypted SOCKS5 proxy
written in OCaml.

###Build
    corebuild -pkg async,core_extended,cryptokit client.native server.native

###Credit to                                                                       
* Jane Street's Core and Async library                                             
* Xavier Leroy's Cryptokit                                                         
* David Sheet's ocaml-libsodium                                                    
* 9gag.com, without whom I would have finished months earlier

###TO-DO
* Support for libsodium, AES-256-CFB, AES-256-OFB and ARCFour encryptions
* Better encryption and decryption modules, more integrated with Async
* UDP relay

###FAQ
**Q**: How asynchrony is achieved?

**A**: In a Monadic way. Specifically, through Async.Deferred.

**Q**: Why encryption? Encryption is not enforced in RFC1928.

**A**: Because f*ck GFW. That's why.

**Q**: Why not use C, Python, or Node.js?

**A**: F*ck C, f*ck Python and f*ck Node.js particularly. Alpaca also shows its indifference to Node.js:

![pic](https://lh3.googleusercontent.com/-AFJqfp3NaDE/U_w2wu6LVzI/AAAAAAAABN4/uKzG2BqSTrc/w852-h764/alpaca_nodejs.gif).



### License
GPL V3

===
### Alpaca

*The habits of spitting and trampling are probably defence mechanisms of the 
animals against outside aggression, real or potential.*

-- [UN FAO Manual for ALPACA RAISING IN THE HIGH ANDES, Behavioural characteristics](http://www.fao.org/docrep/004/x6500e/x6500e21.htm)
