# FormCrypt.go

This is a go module which provides support for browser-side encryption
and server-side decryption using RSA.

It comes with embedded Javascript code as well as a helper function to
generate a ready-to-use snippet for you to directly insert into your webpage.

If you are using PHP, you can refer to the one I wrote a few years ago on gitee:
[fsgmhoward/FormCrypt](https://gitee.com/fsgmhoward/FormCrypt)

[![Build Status](https://travis-ci.com/fsgmhoward/formcrypt.go.svg?branch=main)](https://travis-ci.com/fsgmhoward/formcrypt.go)

## Warning

Even if you are using this module, you should still enable HTTPS on
your website.

Using this module together with HTTPS provides you confidentiality of form data
against those with your HTTPS private key, such as CDN and logger middleware (of
your organization).

However, there is **no integrity, nor authenticity** provided. That is meant
to be provided by HTTPS/TLS. **Never** use this without HTTPS.

Also, securities of using browser-side JS to do encryption can also be
ineffective given many factors like PRNG.

## How to use
You should be able to just import it as a go module.
```
go get github.com/fsgmhoward/formcrypt.go
```

The rest you can take a look at [the example](_example). It should be pretty
straight-forward.

## Development
When you update any assets (those JS), you will need to generate statik module
once again:
```
statik -src=assets -f
```

Also, this module and the coming example were tested under Go 1.14. There is
no guarantee that it will work on other versions (especially the older ones).

## License
This is open-sourced under The 3-Clause BSD License. See [LICENSE](LICENSE)
for exact licensing details.

Client-side JS codes mainly bases on Tom Wu's JSBN library. Please refer to
[its website](http://www-cs-students.stanford.edu/~tjw/jsbn/) for licensing
details.