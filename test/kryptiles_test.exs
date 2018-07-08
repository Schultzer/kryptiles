defmodule KryptilesTest do
  use ExUnit.Case
  use Bitwise

  describe "random_string/1" do
    test "generates the right length string" do
      for n <- 1..1000, do: assert n === byte_size(Kryptiles.random_string(n))
    end

    test "returns an error on invalid bits size" do
      assert Kryptiles.random_string(99999999999999999999) ==  {:error, "failed generating random bits"}
    end
  end

  describe "random_digits/1" do
    test "generates the right length string" do
      for n <- 1..1000, do: assert n === byte_size(Kryptiles.random_digits(n))
    end

    test "returns an error on invalid bits size" do
      assert Kryptiles.random_digits(99999999999999999999) ==  {:error, "failed generating random bits"}
    end

    test "generates equal digits distribution" do
      for d <- digits(), do: assert d in 99000..101000
    end
  end

  def digits(digits \\ [0, 0, 0, 0, 0, 0, 0, 0, 0, 0], size \\ 0)
  def digits(digits, size) when size < 1000000 do
    pos = :erlang.binary_to_integer(Kryptiles.random_digits(1))

    digits
    |> List.replace_at(pos, Enum.at(digits, pos) + 1)
    |> digits(size + 1)
  end
  def digits(digits, _size), do: digits

  describe "random_bits/1" do
    test "returns an error on invalid input" do
      assert Kryptiles.random_bits(0) == {:error, "invalid random bits count"}
    end
  end

  describe "fixed_time_comparison/2" do
    # https://github.com/elixir-lang/plug/blob/master/test/plug/crypto_test.exs#L11-L18
    test "compares binaries securely" do
      assert Kryptiles.fixed_time_comparison(<<>>, <<>>)
      assert Kryptiles.fixed_time_comparison(<<0>>, <<0>>)

      refute Kryptiles.fixed_time_comparison(<<>>, <<1>>)
      refute Kryptiles.fixed_time_comparison(<<1>>, <<>>)
      refute Kryptiles.fixed_time_comparison(<<0>>, <<1>>)
    end
  end

  describe "pbkdf2/4" do
    # https://www.ietf.org/rfc/rfc6070.txt
    test "PBKDF2 with RFC 6070 test vectors" do
      key = Kryptiles.pbkdf2("password", "salt", 20)
      assert Base.encode16(key, case: :lower) === "0c60c80f961f0e71f3a9b524af6012062fe037a6"

      key = Kryptiles.pbkdf2("password", "salt", 20, 2)
      assert Base.encode16(key, case: :lower) === "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"

      key = Kryptiles.pbkdf2("password", "salt", 20, 4096)
      assert Base.encode16(key, case: :lower) === "4b007901b765489abead49d926f721d065a429c1"

      key = Kryptiles.pbkdf2("password", "salt", 20, 16777216)
      assert Base.encode16(key, case: :lower) === "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"

      key = Kryptiles.pbkdf2("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 25, 4096)
      assert Base.encode16(key, case: :lower) === "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"

      key = Kryptiles.pbkdf2("pass\0word", "sa\0lt", 16, 4096)
      assert Base.encode16(key, case: :lower) === "56fa6aa75548099dcc37d7f03425e0c3"
    end

    test "PBKDF2 with SHA256" do
      key = Kryptiles.pbkdf2("password", "salt", 32, 32, :sha256)
      assert Base.encode16(key, case: :lower) === "64c486c55d30d4c5a079b8823b7d7cb37ff0556f537da8410233bcec330ed956"
    end

    test "Keylen to long" do
      assert Kryptiles.pbkdf2("password", "salt", bsl(1, 32) + 1) == {:error, "keylen is 4294967297 the maximum keylen is 4294967295"}
    end
  end
end
