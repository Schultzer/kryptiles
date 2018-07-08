# Kryptiles

[![CircleCI](https://circleci.com/gh/Schultzer/kryptiles.svg?style=svg)](https://circleci.com/gh/Schultzer/kryptiles)


## Examples

```elixir
iex> Kryptiles.random_string(10)
"do77RukqJobZPG3rSJSdCm9JDnX5IT1q"

iex> Kryptiles.random_digits(10)
"3149464061"

iex> Kryptiles.random_bits(10)
<<235, 191>>

iex> Kryptiles.fixed_time_comparison(<<>>, "b0i9XAiBxP")
false

iex> keylen = 20
iex> Kryptiles.pbkdf2("password", "salt", keylen)
<<12, 96, 200, 15, 150, 31, 14, 113, 243, 169, 181, 36, 175, 96, 18, 6, 47, 224,
  55, 166>>
```

## Documentation

[hex documentation for kryptiles](https://hexdocs.pm/kryptiles)


## Installation

```elixir
def deps do
  [{:kryptiles, "~> 0.1.0"}]
end
```

## Acknowledgement

This library was made thanks to [Cryptiles](https://github.com/hapijs/cryptiles) as an implementation in Elixir.

## LICENSE

(The MIT License)

Copyright (c) 2017 Benjamin Schultzer

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the 'Software'), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
