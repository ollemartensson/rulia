FROM julia:1.12-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Project.toml Manifest.toml ./
COPY src/BankidTestAdapter.jl ./src/BankidTestAdapter.jl
RUN julia --project=. -e 'using Pkg; Pkg.instantiate()'
COPY src ./src

EXPOSE 8080
CMD ["julia", "--project=.", "src/main.jl"]
