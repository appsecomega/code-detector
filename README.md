# code-detector (Go)

Gate de esteira Veracode: tem código/artefato escaneável **antes** de empacotar e fazer upload?

- `true` = tem módulo escaneável → faça o upload SAST
- `false` = só SBOM/manifesto/docs (ou só linguagem fora do SAST) → **pule sem erro** em vez de receber `No modules found`

Binário único em Go (stdlib-only, sem dependências), ideal para CI.

## Instalação (via Release)

Baixe o binário pronto na página **Releases** do repositório
(`code-detector_<versão>_<SO>_<arch>.tar.gz` + `checksums.txt`):

```bash
# Exemplo Linux amd64, versão v1.0.0:
curl -sL -o code-detector.tar.gz \
  https://github.com/appsecomega/code-detector/releases/download/v1.0.0/code-detector_v1.0.0_Linux_x86_64.tar.gz
tar -xzf code-detector.tar.gz
./code-detector --version
```

Ou compile localmente:

```bash
go build -o code-detector .
# ou: make build
```

## Uso (verificação pré-empacotamento)

```bash
# 1) Checa o repo/fonte ANTES de zipar:
./code-detector ./meu-repo -q --mode veracode
# true  -> pode empacotar + subir
# false -> pule o SAST (só SBOM/manifesto)

# 2) JSON p/ log da esteira:
./code-detector ./meu-repo --json

# 3) Pipeline com exit code (0=scan, 2=skip):
./code-detector ./meu-repo --mode veracode --fail-on-no-code -q

# 4) Checa o pacote já gerado:
./code-detector app.zip --mode veracode
```

Exemplo shell:

```bash
if [ "$(./code-detector ./src -q --mode veracode)" = "true" ]; then
  zip -r app.zip src/
  # upload veracode...
else
  echo "sem módulo escaneável — pulando SAST sem falhar o build."
fi
```

## Categorias

| categoria | `veracode_scannable` | ação |
|---|---|---|
| `code` | ✅ | `scan` |
| `artifact` (`.jar/.war/.ear/.dll/.exe/.apk/.aar`) | ✅ | `scan` |
| `sbom-only` | ❌ | `skip` |
| `manifest-only` | ❌ | `skip` |
| `code-unsupported-by-veracode` (ex.: só `.sh/.sql/.tf`) | ❌ | `skip` |
| `non-scannable-only` / `empty` | ❌ | `skip` |

## Desenvolvimento

```bash
go test ./...
go vet ./...
gofmt -l .
# ou: make test
```

## Publicando uma nova versão (release automática)

O workflow `.github/workflows/release.yml` publica a Release **sozinho**
sempre que uma tag `v*.*.*` é enviada. Os binários
(linux/darwin/windows × amd64/arm64) + `checksums.txt` vão anexados:

```bash
# 1) Suba o código na main
git push origin main

# 2) Crie e envie a tag da nova versão
git tag v1.1.0
git push origin v1.1.0

# 3) Aguarde o workflow "release" em Actions — a Release aparece pronta p/ baixar.
```

Para testar o empacotamento localmente sem publicar (exige `goreleaser` instalado):

```bash
make snapshot   # gera dist/ local
```
