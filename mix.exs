defmodule Kryptiles.Mixfile do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :kryptiles,
      version: @version,
      elixir: "~> 1.5",
      name: "Kryptiles",
      source_url: "https://github.com/schultzer/kryptiles",
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs()
    ]
  end

  def application do
    [extra_applications: [:crypto, :logger]]
  end

  defp deps do
    [
      {:ex_doc, "~> 0.14", only: :dev},
    ]
  end

  defp description do
    """
    Elixir implementation of https://github.com/hapijs/cryptiles
    """
  end

  defp package do
    [
      name: :kryptiles,
      maintainers: ["Benjamin Schultzer"],
      licenses: ~w(MIT),
      links: links(),
      files: ~w(CHANGELOG* README* config lib mix.exs)
    ]
end

  def docs do
    [
      source_ref: "v#{@version}",
      main: "readme",
      extras: ["README.md", "CHANGELOG.md"]
    ]
  end

  def links do
    %{
      "GitHub"    => "https://github.com/schultzer/kryptiles",
      "Readme"    => "https://github.com/schultzer/kryptiles/blob/v#{@version}/README.md",
      "Changelog" => "https://github.com/schultzer/kryptiles/blob/v#{@version}/CHANGELOG.md"
    }
  end

end
