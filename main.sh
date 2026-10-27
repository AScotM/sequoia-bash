
#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly PROGRAM="Sequaia"
readonly VERSION="2.0.0"
readonly DESCRIPTION="Sequoia OpenPGP Administration Utility"

readonly EXIT_SUCCESS=0
readonly EXIT_FAILURE=1
readonly EXIT_USAGE=2
readonly EXIT_DEPENDENCY=3
readonly EXIT_INPUT=4
readonly EXIT_OUTPUT=5
readonly EXIT_CRYPTO=6
readonly EXIT_VERIFY=7

VERBOSE=0
QUIET=0
DRY_RUN=0
FORCE=0
JSON=0

OUTPUT=""
LOG_FILE=""
WORK_DIR=""
ACTIVE_TEMP=""
START_TIME="${EPOCHSECONDS:-0}"

declare -a TEMP_FILES=()
declare -a BATCH_RESULTS=()

timestamp() {
    date -u '+%Y-%m-%dT%H:%M:%SZ'
}

log() {
    local level="$1"
    shift

    local message="$*"
    local entry

    entry="$(timestamp) [$level] $message"

    if [[ -n "$LOG_FILE" ]]; then
        printf '%s\n' "$entry" >> "$LOG_FILE"
    fi

    if (( QUIET == 0 )); then
        case "$level" in
            ERROR|WARN)
                printf '%s\n' "$entry" >&2
                ;;
            DEBUG)
                if (( VERBOSE == 1 )); then
                    printf '%s\n' "$entry" >&2
                fi
                ;;
            *)
                printf '%s\n' "$entry" >&2
                ;;
        esac
    fi
}

die() {
    local code="$1"
    shift

    log ERROR "$*"
    exit "$code"
}

cleanup() {
    local file

    for file in "${TEMP_FILES[@]}"; do
        if [[ -n "$file" && -e "$file" ]]; then
            rm -f -- "$file" || true
        fi
    done

    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
        rm -rf -- "$WORK_DIR" || true
    fi
}

on_error() {
    local status="$1"
    local line="$2"

    log DEBUG "Command failed at line $line with status $status"
}

trap cleanup EXIT
trap 'on_error "$?" "$LINENO"' ERR
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
    cat <<EOF
$PROGRAM $VERSION
$DESCRIPTION

Usage:
  $0 [OPTIONS] COMMAND [ARGUMENTS]

Commands:
  info
  doctor
  generate NAME EMAIL
  encrypt FILE CERTIFICATE
  decrypt FILE KEY
  sign FILE KEY
  verify FILE SIGNATURE CERTIFICATE
  inspect CERTIFICATE
  fingerprint CERTIFICATE
  checksum FILE
  batch-encrypt DIRECTORY CERTIFICATE
  batch-sign DIRECTORY KEY
  help

Options:
  -o, --output PATH
  -l, --log FILE
  -v, --verbose
  -q, --quiet
  -n, --dry-run
  -f, --force
  -j, --json
  -h, --help
  --version

Examples:
  $0 info
  $0 doctor
  $0 generate "Example User" "user@example.org"
  $0 encrypt document.txt recipient.cert.pgp
  $0 decrypt document.txt.pgp secret.key.pgp
  $0 sign document.txt secret.key.pgp
  $0 verify document.txt document.txt.sig recipient.cert.pgp
  $0 inspect recipient.cert.pgp
  $0 fingerprint recipient.cert.pgp
  $0 checksum document.txt
  $0 batch-encrypt ./documents recipient.cert.pgp

Security:
  Newly created files use restrictive permissions.
  Existing output files are protected by default.
  Temporary files are created in the destination directory.
  Output files are committed only after successful operations.
  Secret keys are never intentionally printed or logged.
EOF
}

require_command() {
    local command="$1"

    command -v "$command" >/dev/null 2>&1 ||
        die "$EXIT_DEPENDENCY" "Required command unavailable: $command"
}

require_sq() {
    require_command sq
}

require_file() {
    local file="$1"

    [[ -f "$file" ]] ||
        die "$EXIT_INPUT" "File does not exist: $file"

    [[ -r "$file" ]] ||
        die "$EXIT_INPUT" "File is not readable: $file"
}

require_directory() {
    local directory="$1"

    [[ -d "$directory" ]] ||
        die "$EXIT_INPUT" "Directory does not exist: $directory"

    [[ -r "$directory" && -x "$directory" ]] ||
        die "$EXIT_INPUT" "Directory is not accessible: $directory"
}

require_parent() {
    local file="$1"
    local parent

    parent="$(dirname -- "$file")"

    [[ -d "$parent" ]] ||
        die "$EXIT_OUTPUT" "Output directory does not exist: $parent"

    [[ -w "$parent" ]] ||
        die "$EXIT_OUTPUT" "Output directory is not writable: $parent"
}

require_unused_output() {
    local file="$1"

    if [[ -e "$file" || -L "$file" ]]; then
        if (( FORCE == 0 )); then
            die "$EXIT_OUTPUT" "Output already exists: $file"
        fi

        [[ -f "$file" && ! -L "$file" ]] ||
            die "$EXIT_OUTPUT" "Refusing to replace non-regular output: $file"
    fi
}

absolute_path() {
    local path="$1"

    if [[ "$path" == /* ]]; then
        printf '%s\n' "$path"
    else
        printf '%s/%s\n' "$PWD" "$path"
    fi
}

validate_output() {
    local source="$1"
    local destination="$2"
    local source_abs
    local destination_abs

    source_abs="$(absolute_path "$source")"
    destination_abs="$(absolute_path "$destination")"

    [[ "$source_abs" != "$destination_abs" ]] ||
        die "$EXIT_OUTPUT" "Input and output paths are identical"

    if [[ -e "$source" && -e "$destination" ]]; then
        [[ ! "$source" -ef "$destination" ]] ||
            die "$EXIT_OUTPUT" "Input and output refer to the same file"
    fi

    require_parent "$destination"
    require_unused_output "$destination"
}

make_temp() {
    local destination="$1"
    local parent
    local temp

    parent="$(dirname -- "$destination")"

    temp="$(mktemp "$parent/.sequaia.XXXXXXXX")" ||
        die "$EXIT_OUTPUT" "Cannot create temporary file"

    TEMP_FILES+=("$temp")
    ACTIVE_TEMP="$temp"

    printf '%s\n' "$temp"
}

commit_output() {
    local temporary="$1"
    local destination="$2"
    local mode="${3:-600}"

    chmod "$mode" "$temporary" ||
        die "$EXIT_OUTPUT" "Cannot set output permissions"

    if (( FORCE == 1 )); then
        [[ ! -L "$destination" ]] ||
            die "$EXIT_OUTPUT" "Refusing symbolic-link destination"

        mv -fT -- "$temporary" "$destination" ||
            die "$EXIT_OUTPUT" "Cannot commit output"
    else
        if [[ -e "$destination" || -L "$destination" ]]; then
            die "$EXIT_OUTPUT" "Output appeared during operation"
        fi

        ln -- "$temporary" "$destination" ||
            die "$EXIT_OUTPUT" "Cannot commit output"

        rm -f -- "$temporary"
    fi
}

run_sq() {
    require_sq

    if (( DRY_RUN == 1 )); then
        log INFO "Dry run: cryptographic operation skipped"
        return 0
    fi

    sq "$@"
}

json_escape() {
    local value="$1"

    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"

    printf '%s' "$value"
}

result() {
    local operation="$1"
    local status="$2"
    local path="${3:-}"

    if (( JSON == 1 )); then
        printf '{"program":"%s","version":"%s","operation":"%s","status":"%s","path":"%s"}\n' \
            "$(json_escape "$PROGRAM")" \
            "$(json_escape "$VERSION")" \
            "$(json_escape "$operation")" \
            "$(json_escape "$status")" \
            "$(json_escape "$path")"
    else
        printf '%s: %s\n' "$operation" "$status"

        if [[ -n "$path" ]]; then
            printf 'Output: %s\n' "$path"
        fi
    fi
}

validate_identity() {
    local name="$1"
    local email="$2"

    [[ -n "$name" ]] ||
        die "$EXIT_USAGE" "Name cannot be empty"

    [[ "$name" != *$'\n'* && "$name" != *$'\r'* ]] ||
        die "$EXIT_USAGE" "Invalid name"

    [[ "$name" != *'<'* && "$name" != *'>'* ]] ||
        die "$EXIT_USAGE" "Name contains invalid characters"

    [[ "$email" =~ ^[^[:space:]@\<\>]+@[^[:space:]@\<\>]+$ ]] ||
        die "$EXIT_USAGE" "Invalid email address"
}

safe_prefix() {
    local value="$1"

    value="${value//@/_}"
    value="${value//[^a-zA-Z0-9._-]/_}"

    [[ -n "$value" ]] ||
        die "$EXIT_USAGE" "Cannot derive safe filename"

    printf '%s\n' "$value"
}

generate_key() {
    local name="$1"
    local email="$2"
    local prefix
    local key
    local cert
    local temp_key
    local temp_cert

    validate_identity "$name" "$email"

    prefix="$(safe_prefix "$email")"

    key="${OUTPUT:-${prefix}.key.pgp}"
    cert="${key%.key.pgp}.cert.pgp"

    if [[ "$cert" == "$key" ]]; then
        cert="${key}.cert.pgp"
    fi

    validate_output "/dev/null" "$key"
    validate_output "/dev/null" "$cert"

    if (( DRY_RUN == 1 )); then
        result generate planned "$key"
        return
    fi

    temp_key="$(make_temp "$key")"
    temp_cert="$(make_temp "$cert")"

    rm -f -- "$temp_key" "$temp_cert"

    log INFO "Generating OpenPGP key"

    if ! run_sq key generate \
        --userid "$name <$email>" \
        --output "$temp_key"; then
        die "$EXIT_CRYPTO" "Key generation failed"
    fi

    [[ -s "$temp_key" ]] ||
        die "$EXIT_CRYPTO" "Generated secret key is empty"

    chmod 600 "$temp_key"

    if ! run_sq key extract-cert \
        --output "$temp_cert" \
        "$temp_key"; then
        die "$EXIT_CRYPTO" "Certificate extraction failed"
    fi

    [[ -s "$temp_cert" ]] ||
        die "$EXIT_CRYPTO" "Extracted certificate is empty"

    commit_output "$temp_cert" "$cert" 644
    commit_output "$temp_key" "$key" 600

    result generate success "$key"

    if (( JSON == 0 )); then
        printf 'Certificate: %s\n' "$cert"
    fi
}

encrypt_file() {
    local file="$1"
    local certificate="$2"
    local destination
    local temporary

    require_file "$file"
    require_file "$certificate"

    destination="${OUTPUT:-${file}.pgp}"

    validate_output "$file" "$destination"

    if (( DRY_RUN == 1 )); then
        result encrypt planned "$destination"
        return
    fi

    temporary="$(make_temp "$destination")"
    rm -f -- "$temporary"

    log INFO "Encrypting file"

    if ! run_sq encrypt \
        --recipient-file "$certificate" \
        --output "$temporary" \
        "$file"; then
        die "$EXIT_CRYPTO" "Encryption failed"
    fi

    [[ -s "$temporary" ]] ||
        die "$EXIT_CRYPTO" "Encryption produced no output"

    commit_output "$temporary" "$destination" 600

    result encrypt success "$destination"
}

decrypt_file() {
    local file="$1"
    local key="$2"
    local destination
    local temporary

    require_file "$file"
    require_file "$key"

    destination="${OUTPUT:-${file%.pgp}.decrypted}"

    validate_output "$file" "$destination"

    if (( DRY_RUN == 1 )); then
        result decrypt planned "$destination"
        return
    fi

    temporary="$(make_temp "$destination")"
    rm -f -- "$temporary"

    log INFO "Decrypting file"

    if ! run_sq decrypt \
        --key-file "$key" \
        --output "$temporary" \
        "$file"; then
        die "$EXIT_CRYPTO" "Decryption failed"
    fi

    [[ -f "$temporary" ]] ||
        die "$EXIT_CRYPTO" "Decryption did not create output"

    commit_output "$temporary" "$destination" 600

    result decrypt success "$destination"
}

sign_file() {
    local file="$1"
    local key="$2"
    local destination
    local temporary

    require_file "$file"
    require_file "$key"

    destination="${OUTPUT:-${file}.sig}"

    validate_output "$file" "$destination"

    if (( DRY_RUN == 1 )); then
        result sign planned "$destination"
        return
    fi

    temporary="$(make_temp "$destination")"
    rm -f -- "$temporary"

    log INFO "Creating detached signature"

    if ! run_sq sign \
        --signer-file "$key" \
        --detached \
        --output "$temporary" \
        "$file"; then
        die "$EXIT_CRYPTO" "Signing failed"
    fi

    [[ -s "$temporary" ]] ||
        die "$EXIT_CRYPTO" "Signing produced an empty signature"

    commit_output "$temporary" "$destination" 644

    result sign success "$destination"
}

verify_file() {
    local file="$1"
    local signature="$2"
    local certificate="$3"

    require_file "$file"
    require_file "$signature"
    require_file "$certificate"

    if (( DRY_RUN == 1 )); then
        result verify planned "$file"
        return
    fi

    log INFO "Verifying detached signature"

    if ! run_sq verify \
        --signer-file "$certificate" \
        --detached "$signature" \
        "$file"; then
        die "$EXIT_VERIFY" "Signature verification failed"
    fi

    result verify success "$file"
}

inspect_certificate() {
    local certificate="$1"

    require_file "$certificate"
    require_sq

    if (( DRY_RUN == 1 )); then
        result inspect planned "$certificate"
        return
    fi

    sq inspect "$certificate"
}

fingerprint_certificate() {
    local certificate="$1"

    require_file "$certificate"
    require_sq

    if (( DRY_RUN == 1 )); then
        result fingerprint planned "$certificate"
        return
    fi

    sq inspect "$certificate"
}

checksum_file() {
    local file="$1"

    require_file "$file"
    require_command sha256sum

    if (( DRY_RUN == 1 )); then
        result checksum planned "$file"
        return
    fi

    sha256sum -- "$file"
}

batch_encrypt() {
    local directory="$1"
    local certificate="$2"
    local file
    local count=0
    local failures=0

    require_directory "$directory"
    require_file "$certificate"

    [[ -z "$OUTPUT" ]] ||
        die "$EXIT_USAGE" "--output is unsupported for batch operations"

    while IFS= read -r -d '' file; do
        [[ "$file" != *.pgp ]] || continue

        if (
            encrypt_file "$file" "$certificate"
        ); then
            ((count += 1))
        else
            ((failures += 1))
        fi
    done < <(
        find "$directory" \
            -maxdepth 1 \
            -type f \
            -print0
    )

    log INFO "Encrypted files: $count"
    log INFO "Failed files: $failures"

    (( failures == 0 )) ||
        die "$EXIT_CRYPTO" "Batch encryption incomplete"
}

batch_sign() {
    local directory="$1"
    local key="$2"
    local file
    local count=0
    local failures=0

    require_directory "$directory"
    require_file "$key"

    [[ -z "$OUTPUT" ]] ||
        die "$EXIT_USAGE" "--output is unsupported for batch operations"

    while IFS= read -r -d '' file; do
        [[ "$file" != *.sig ]] || continue

        if (
            sign_file "$file" "$key"
        ); then
            ((count += 1))
        else
            ((failures += 1))
        fi
    done < <(
        find "$directory" \
            -maxdepth 1 \
            -type f \
            -print0
    )

    log INFO "Signed files: $count"
    log INFO "Failed files: $failures"

    (( failures == 0 )) ||
        die "$EXIT_CRYPTO" "Batch signing incomplete"
}

show_info() {
    require_sq

    if (( JSON == 1 )); then
        printf '{"program":"%s","version":"%s","sq_version":"%s"}\n' \
            "$PROGRAM" \
            "$VERSION" \
            "$(json_escape "$(sq --version)")"
    else
        printf '%s %s\n' "$PROGRAM" "$VERSION"
        printf '%s\n' "$DESCRIPTION"
        printf '\n'

        sq --version
    fi
}

doctor() {
    local failures=0
    local command

    printf '%s diagnostics\n' "$PROGRAM"
    printf '\n'

    for command in \
        sq \
        mktemp \
        sha256sum \
        find \
        chmod \
        mv \
        ln \
        rm \
        date; do

        if command -v "$command" >/dev/null 2>&1; then
            printf '[OK] %s\n' "$command"
        else
            printf '[MISSING] %s\n' "$command"
            ((failures += 1))
        fi
    done

    printf '\n'

    if command -v sq >/dev/null 2>&1; then
        sq --version
    fi

    printf '\n'
    printf 'Current umask: '
    umask

    printf 'Working directory: %s\n' "$PWD"

    if (( failures > 0 )); then
        die "$EXIT_DEPENDENCY" "$failures dependencies unavailable"
    fi

    result doctor success
}

parse_options() {
    POSITIONAL=()

    while (( $# > 0 )); do
        case "$1" in
            -o|--output)
                (( $# >= 2 )) ||
                    die "$EXIT_USAGE" "Missing output path"

                OUTPUT="$2"
                shift 2
                ;;
            -l|--log)
                (( $# >= 2 )) ||
                    die "$EXIT_USAGE" "Missing log path"

                LOG_FILE="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -q|--quiet)
                QUIET=1
                shift
                ;;
            -n|--dry-run)
                DRY_RUN=1
                shift
                ;;
            -f|--force)
                FORCE=1
                shift
                ;;
            -j|--json)
                JSON=1
                shift
                ;;
            -h|--help)
                usage
                exit "$EXIT_SUCCESS"
                ;;
            --version)
                printf '%s\n' "$VERSION"
                exit "$EXIT_SUCCESS"
                ;;
            --)
                shift

                while (( $# > 0 )); do
                    POSITIONAL+=("$1")
                    shift
                done
                ;;
            -*)
                die "$EXIT_USAGE" "Unknown option: $1"
                ;;
            *)
                POSITIONAL+=("$1")
                shift
                ;;
        esac
    done
}

require_arguments() {
    local expected="$1"
    local actual="$2"

    (( actual == expected )) ||
        die "$EXIT_USAGE" "Expected $expected arguments, received $actual"
}

main() {
    parse_options "$@"

    local command="${POSITIONAL[0]:-help}"
    local -a arguments=()

    if (( ${#POSITIONAL[@]} > 1 )); then
        arguments=("${POSITIONAL[@]:1}")
    fi

    if [[ -n "$LOG_FILE" ]]; then
        require_parent "$LOG_FILE"

        if [[ -L "$LOG_FILE" ]]; then
            die "$EXIT_OUTPUT" "Refusing symbolic-link log path"
        fi

        touch -- "$LOG_FILE"
        chmod 600 "$LOG_FILE"
    fi

    log DEBUG "Starting $PROGRAM $VERSION"

    case "$command" in
        info)
            require_arguments 0 "${#arguments[@]}"
            show_info
            ;;
        doctor)
            require_arguments 0 "${#arguments[@]}"
            doctor
            ;;
        generate)
            require_arguments 2 "${#arguments[@]}"
            generate_key "${arguments[0]}" "${arguments[1]}"
            ;;
        encrypt)
            require_arguments 2 "${#arguments[@]}"
            encrypt_file "${arguments[0]}" "${arguments[1]}"
            ;;
        decrypt)
            require_arguments 2 "${#arguments[@]}"
            decrypt_file "${arguments[0]}" "${arguments[1]}"
            ;;
        sign)
            require_arguments 2 "${#arguments[@]}"
            sign_file "${arguments[0]}" "${arguments[1]}"
            ;;
        verify)
            require_arguments 3 "${#arguments[@]}"
            verify_file \
                "${arguments[0]}" \
                "${arguments[1]}" \
                "${arguments[2]}"
            ;;
        inspect)
            require_arguments 1 "${#arguments[@]}"
            inspect_certificate "${arguments[0]}"
            ;;
        fingerprint)
            require_arguments 1 "${#arguments[@]}"
            fingerprint_certificate "${arguments[0]}"
            ;;
        checksum)
            require_arguments 1 "${#arguments[@]}"
            checksum_file "${arguments[0]}"
            ;;
        batch-encrypt)
            require_arguments 2 "${#arguments[@]}"
            batch_encrypt "${arguments[0]}" "${arguments[1]}"
            ;;
        batch-sign)
            require_arguments 2 "${#arguments[@]}"
            batch_sign "${arguments[0]}" "${arguments[1]}"
            ;;
        help)
            usage
            ;;
        *)
            die "$EXIT_USAGE" "Unknown command: $command"
            ;;
    esac
}

main "$@"
