#!/bin/bash
# Script to review multiple git commits using AI

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REVIEW_SCRIPT="$SCRIPT_DIR/review.py"
GIT_ROOT="$(git rev-parse --show-toplevel)"
WORK_DIR="$GIT_ROOT/.ci/ai_review/reviews"

# Check if API key is set
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "Error: ANTHROPIC_API_KEY environment variable not set"
    echo "Please set it with: export ANTHROPIC_API_KEY='your-api-key'"
    exit 1
fi

# Function to extract email header
extract_header() {
    local file="$1"
    local header="$2"
    # Extract header value, handling multi-line headers
    awk -v header="$header:" '
        tolower($0) ~ "^" tolower(header) {
            sub(/^[^:]+: */, "")
            value = $0
            # Handle continuation lines (starting with whitespace)
            while (getline > 0 && /^[ \t]/) {
                sub(/^[ \t]+/, " ")
                value = value $0
            }
            print value
            exit
        }
    ' "$file"
}

# Function to check if patch has email headers
has_email_headers() {
    local file="$1"
    grep -q "^Message-ID:" "$file" || grep -q "^Message-Id:" "$file"
}

# Function to generate email headers for reply
generate_email_headers() {
    local to="$1"
    local subject="$2"
    local message_id="$3"
    local references="$4"

    # Generate To: header
    if [ -n "$to" ]; then
        echo "To: $to"
    fi

    # Generate Subject: header
    if [ -n "$subject" ]; then
        # Remove any existing Re: prefix and add our own
        subject=$(echo "$subject" | sed 's/^[Rr][Ee]: *//')
        echo "Subject: Re: $subject"
    fi

    # Generate In-Reply-To: header
    if [ -n "$message_id" ]; then
        echo "In-Reply-To: $message_id"
    fi

    # Generate References: header
    if [ -n "$message_id" ]; then
        # Add the original Message-ID to references
        if [ -n "$references" ]; then
            # Append to existing references
            echo "References: $references $message_id"
        else
            echo "References: $message_id"
        fi
    elif [ -n "$references" ]; then
        echo "References: $references"
    fi

    echo ""
}

usage() {
    cat <<EOF
Usage: $0 <commit1> <commit2> [commit3 ...]
Usage: $0 <patch or mbox file>

Review multiple git commits using AI-powered code review.

Arguments:
  commit1 commit2 ...   Git commit IDs to review (can be SHAs, branches, tags,
                         etc.)
  patch or mbox file... Patch file or MBOX file.

Options:
  --output-dir DIR     Directory to save reviews (default: .ci/ai_review/reviews)
  --prompt PROMPT      Prompt to use (default: review-start)
  --help               Show this help message

Examples:
  # Review last 3 commits
  $0 HEAD~2 HEAD~1 HEAD

  # Review a range of commits
  $0 \$(git rev-list main..feature-branch)

  # Review specific commits
  $0 abc123 def456 789ghi

Output:
  Reviews will be saved in the output directory as:
    message_0001  (review of first commit)
    message_0002  (review of second commit)
    ...
EOF
    exit 0
}

# Parse arguments
OUTPUT_DIR=""
PROMPT="review-start"
COMMITS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            usage
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --prompt)
            PROMPT="$2"
            shift 2
            ;;
        *)
            COMMITS+=("$1")
            shift
            ;;
    esac
done

# Check if commits were provided
if [ ${#COMMITS[@]} -eq 0 ]; then
    echo "Error: No commits specified"
    echo ""
    usage
fi

# Set default output directory if not specified
if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="$WORK_DIR"
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "==================================="
echo "AI Review Tool - Batch Mode"
echo "==================================="
echo "Git Root: $GIT_ROOT"
echo "Output Directory: $OUTPUT_DIR"
echo "Prompt: $PROMPT"
echo "Number of commits: ${#COMMITS[@]}"
echo ""

# Save current branch/HEAD for restoration
ORIGINAL_HEAD=$(git rev-parse HEAD)
ORIGINAL_BRANCH=$(git symbolic-ref -q HEAD || echo "")

# Function to restore git state
restore_git_state() {
    echo ""
    echo "Restoring git state..."
    if [ -n "$ORIGINAL_BRANCH" ]; then
        git checkout -q "${ORIGINAL_BRANCH#refs/heads/}"
    else
        git checkout -q "$ORIGINAL_HEAD"
    fi
}

# Set trap to restore state on exit
trap restore_git_state EXIT

# Process each commit
counter=1
for commit in "${COMMITS[@]}"; do
    # Format counter with leading zeros (0001, 0002, etc.)
    counter_formatted=$(printf "%04d" $counter)
    PATCH_FILE="$OUTPUT_DIR/patch_${counter_formatted}.patch"

    if [ ! -f "$commit" ]; then
        echo "==================================="
        echo "Processing commit $counter_formatted: $commit"
        echo "==================================="

        # Verify commit exists
        if ! git rev-parse --verify "$commit" >/dev/null 2>&1; then
            echo "Error: Invalid commit: $commit"
            echo "Skipping..."
            echo ""
            counter=$((counter + 1))
            continue
        fi

        # Get full commit SHA
        COMMIT_SHA=$(git rev-parse "$commit")
        echo "Commit SHA: $COMMIT_SHA"

        # Reset tree to COMMIT~1
        PARENT_COMMIT="${COMMIT_SHA}~1"

        # Check if parent exists (not initial commit)
        if git rev-parse --verify "$PARENT_COMMIT" >/dev/null 2>&1; then
            echo "Checking out parent: $PARENT_COMMIT"
            git checkout -q "$PARENT_COMMIT"
        else
            echo "This is the initial commit, checking out commit itself"
            git checkout -q "$COMMIT_SHA"
        fi

        # Generate patch file
        echo "Generating patch: $PATCH_FILE"
        git format-patch -1 "$COMMIT_SHA" --stdout > "$PATCH_FILE"
    else
        echo "==================================="
        echo "Processing Patch $counter_formatted: $commit"
        echo "==================================="

        cp "$commit" "$PATCH_FILE"
    fi

    # Run review to temporary file first
    TEMP_REVIEW=$(mktemp)
    echo "Running AI review..."
    echo "Output: $OUTPUT_FILE"

    if "$REVIEW_SCRIPT" "$PATCH_FILE" --prompt "$PROMPT" --output "$TEMP_REVIEW"; then
        echo "✓ Review completed successfully"

        # Check if patch has email headers
        if has_email_headers "$PATCH_FILE"; then
            echo "  Detected email headers, formatting as reply..."

            # Extract email headers
            FROM=$(extract_header "$PATCH_FILE" "From")
            SUBJECT=$(extract_header "$PATCH_FILE" "Subject")
            MESSAGE_ID=$(extract_header "$PATCH_FILE" "Message-ID")
            [ -z "$MESSAGE_ID" ] && MESSAGE_ID=$(extract_header "$PATCH_FILE" "Message-Id")
            REFERENCES=$(extract_header "$PATCH_FILE" "References")

            # Create output with email headers
            OUTPUT_FILE="$OUTPUT_DIR/message_${counter_formatted}"
            {
                generate_email_headers "$FROM" "$SUBJECT" "$MESSAGE_ID" "$REFERENCES"
                cat "$TEMP_REVIEW"
            } > "$OUTPUT_FILE"

            echo "  To: $FROM"
            echo "  Subject: Re: $(echo "$SUBJECT" | sed 's/^[Rr][Ee]: *//')"
        else
            # No email headers, just copy the review
            OUTPUT_FILE="$OUTPUT_DIR/message_${counter_formatted}"
            cp "$TEMP_REVIEW" "$OUTPUT_FILE"
        fi

        rm -f "$TEMP_REVIEW"

        # Show summary
        REVIEW_SIZE=$(wc -l < "$OUTPUT_FILE")
        echo "  Review size: $REVIEW_SIZE lines"
    else
        echo "✗ Review failed"
        rm -f "$TEMP_REVIEW"
        echo "  Check $OUTPUT_FILE for details"
    fi

    if [ -f "$commit" ]; then
        echo "✓ Advancing tree by running [ git am \"$commit\" ]..."
        git am "$commit"
    fi

    echo ""
    counter=$((counter + 1))
done

# Restore git state (will also be called by trap)
restore_git_state

echo "==================================="
echo "All reviews completed!"
echo "==================================="
echo "Output directory: $OUTPUT_DIR"
echo "Files generated:"
ls -1 "$OUTPUT_DIR"/message_* 2>/dev/null | while read -r file; do
    echo "  - $(basename "$file")"
done
echo ""
echo "To view a review:"
echo "  cat $OUTPUT_DIR/message_0001"
