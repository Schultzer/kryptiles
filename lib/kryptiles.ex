defmodule Kryptiles do
  @moduledoc """
  """

  use Bitwise

  @doc """
  Returns a cryptographically strong pseudo-random data string.
  Takes a size argument for the length of the string.

  ## Examples

      iex> Kryptiles.random_string(0)
      ""

      iex> Kryptiles.random_string(10)
      "do77RukqJobZPG3rSJSdCm9JDnX5IT1q"
  """
  @spec random_string(integer()) :: binary() | {:error, binary()}
  def random_string(size) when is_integer(size) do
    size
    |> Kernel.+(1)
    |> Kernel.*(6)
    |> random_bits()
    |> case do
        {:error, reason} -> {:error, reason}

        bytes ->
          bytes
          |> Base.url_encode64()
          |> String.slice(0, size)
       end
  end

  @doc """
  Returns a cryptographically strong pseudo-random data string consisting of only numerical digits (0-9).
  Takes a size argument for the length of the string.

  ## Examples

      iex> Kryptiles.random_digits(1)
      "9"

      iex> Kryptiles.random_digits(10)
      "3149464061"
  """
  @spec random_digits(integer()) :: binary() | {:error, binary()}
  def random_digits(size) do
    size
    |> Kernel.*(2)
    |> random()
    |> digits(size)
  end

  defp digits(buffer, size, digits \\ [], pos \\ 0)
  defp digits({:error, reason}, _, _, _), do: {:error, reason}
  defp digits(_buffer, size, digits, _pos) when length(digits) == size do
    digits
    |> Enum.reverse()
    |> Enum.join()
  end
  defp digits(buffer, size, digits, pos) when length(digits) < size and pos >= byte_size(buffer) do
    size * 2
    |> random()
    |> digits(size, digits)
  end
  defp digits(buffer, size, digits, pos) when length(digits) < size do
    case :erlang.binary_part(buffer, pos, 1) do
      <<part::integer()>> when part < 250 -> digits(buffer, size, ["#{Integer.mod(part, 10)}" | digits], pos + 1)

      _                                   -> digits(buffer, size, digits, pos + 1)
    end
  end

  @doc """
  Returns a cryptographically strong pseudo-random bytes
  Takes a size argument for the length of the string.

  ## Examples

      iex> Kryptiles.random_bits(1)
      <<236>>

      iex> Kryptiles.random_bits(10)
      <<235, 191>>
  """
  @spec random_bits(integer()) :: binary() | {:error, binary()}
  def random_bits(bits) when bits <= 0, do: {:error, "invalid random bits count"}
  def random_bits(bits) do
    bits
    |> Kernel./(8)
    |> Float.ceil()
    |> Kernel.round()
    |> random()
  end

  @doc false
  @spec random(integer()) :: binary() | {:error, binary()}
  def random(bytes) do
    try do
      :crypto.strong_rand_bytes(bytes)
    rescue
      ArgumentError -> {:error, "failed generating random bits"}
    end
  end

  # https://github.com/elixir-lang/plug/blob/master/lib/plug/crypto.ex#L94-L114
  # http://codahale.com/a-lesson-in-timing-attacks/
  @doc """
  Compare two strings using fixed time algorithm (to prevent time-based analysis of MAC digest match).
  Returns `true` if the strings match, `false` if they differ.

  ## Examples

      iex> Kryptiles.fixed_time_comparison(<<>>, <<>>)
      true

      iex> Kryptiles.fixed_time_comparison(<<>>, "b0i9XAiBxP")
      false
  """
  @spec fixed_time_comparison(binary(), binary()) :: true | false
  def fixed_time_comparison(left, right) when byte_size(left) == byte_size(right) do
    __fixed_time_comparison__(left, right) == 0
  end
  def fixed_time_comparison(_left, _right), do: false

  defp __fixed_time_comparison__(left, right, acc \\ 0)
  defp __fixed_time_comparison__(<<>>, <<>>, acc), do: acc
  defp __fixed_time_comparison__(<<x, left::binary()>>, <<y, right::binary()>>, acc) do
    __fixed_time_comparison__(left, right, acc ||| (x ^^^ y))
  end

  # bsl(1, 32) - 1 === 4294967295
  @doc """
  Computes a pbkdf2 bitstring [RFC 2898](https://tools.ietf.org/html/rfc2898)

  * `options` are an `Enumerable.t()` with these keys:
    * `digest` is any of `:md5 | :sha | :sha224 | :sha256 | :sha384 | :sha512 ` defaults to `:sha`
    * `iterations` is a `non_neg_integer()` defaults to `1`


  ## Examples

      iex> keylen = 20
      iex> Kryptiles.pbkdf2("password", "salt", keylen)
      <<12, 96, 200, 15, 150, 31, 14, 113, 243, 169, 181, 36, 175, 96, 18, 6, 47, 224,
        55, 166>>
  """
  @spec pbkdf2(binary(), binary(), pos_integer(), pos_integer, atom()) :: binary() | {:error, binary()}
  def pbkdf2(password, salt, keylen, iterations \\ 1, digest \\ :sha)
  def pbkdf2(_password, _salt, keylen, _iterations, _digest) when not is_integer(keylen) do
    {:error, "invalid keylen: #{inspect keylen}"}
  end
  def pbkdf2(_password, _salt, keylen, _iterations, _digest) when keylen > 4294967295 do
    {:error, "keylen is #{inspect keylen} the maximum keylen is 4294967295"}
  end
  def pbkdf2(_password, _salt, _keylen, iterations, _digest) when not is_integer(iterations) do
    {:error, "invalid iterations: #{inspect iterations}"}
  end
  for digest <- ~w(md5 sha sha224 sha256 sha384 sha512)a do
    def pbkdf2(password, salt, keylen, iterations, unquote(digest)), do: __pbkdf2__(mac_fun(unquote(digest), password), salt, keylen, iterations)
  end
  def pbkdf2(_password, _salt, _keylen, _iterations, digest), do: {:error, "unknown digest: #{inspect digest}"}

  defp __pbkdf2__(fun, salt, keylen, iterations, block_index \\ 1, length \\ 0, acc \\ [])
  defp __pbkdf2__(_fun, _salt, keylen, _iterations, _block_index, length, acc) when length >= keylen do
    acc
    |> :erlang.iolist_to_binary()
    |> :erlang.binary_part(0, keylen)
  end
  defp __pbkdf2__(fun, salt, keylen, iterations, block_index, length, acc) do
    initial = fun.(<<salt::binary, block_index::integer-size(32)>>)
    block = iterate(fun, iterations - 1, initial, initial)
    __pbkdf2__(fun, salt, keylen, iterations, block_index + 1, byte_size(block) + length, [acc | block])
  end

  defp iterate(_fun, 0, _prev, acc), do: acc
  defp iterate(fun, iteration, prev, acc) do
    next = fun.(prev)
    iterate(fun, iteration - 1, next, :crypto.exor(next, acc))
  end

  defp mac_fun(digest, secret) do
    &:crypto.hmac(digest, secret, &1)
  end
end
