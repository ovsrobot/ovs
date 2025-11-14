# AI Review Suite for OVS

This directory contains tools for conducting AI-powered code reviews of OVS 
patches using Claude (Anthropic API).

## Setup

1. Install the required Python packages:
   ```bash
   pip install -r .ci/ai_review/requirements.txt
   ```

   Or install directly:
   ```bash
   pip install anthropic
   ```

2. Set your Anthropic API key:
   ```bash
   export ANTHROPIC_API_KEY='your-api-key-here'
   ```

## Usage

### Batch Review Multiple Commits (Recommended)

The easiest way to review multiple commits or email patches is using the
`run_code_review_session.sh` script:

```bash
# Review last 3 commits
.ci/ai_review/run_code_review_session.sh HEAD~2 HEAD~1 HEAD

# Review a range of commits from a branch
.ci/ai_review/run_code_review_session.sh $(git rev-list main..feature-branch)

# Review specific commits
.ci/ai_review/run_code_review_session.sh abc123 def456 789ghi

# Review patch files from email (with automatic email reply formatting)
.ci/ai_review/run_code_review_session.sh patch1.patch patch2.patch

# Custom output directory
.ci/ai_review/run_code_review_session.sh HEAD~2 HEAD~1 HEAD \
    --output-dir /tmp/reviews
```

The script will:
1. Generate patches for each commit using `git format-patch` (or use provided
patch files)
2. Reset the tree to each commit's parent (for git commits)
3. Run the AI review
4. **If patch has email headers**: Format output as email reply with proper 
To:, Subject:, In-Reply-To:, and References: headers
5. Save outputs as `message_0001`, `message_0002`, etc.
6. Restore your original git state when done

#### Email Header Support

When reviewing patches from email (e.g., from a mailing list), the script 
automatically:
- Detects email headers (Message-ID, From, Subject, etc.)
- Formats the review output as a proper email reply:
  - `To:` set to the original patch author (From:)
  - `Subject:` prefixed with "Re:"
  - `In-Reply-To:` set to original Message-ID
  - `References:` includes the original Message-ID and any existing references

This makes it easy to send the review back to the mailing list as a proper 
threaded reply.

### Basic Review (Single Patch)

To review a patch file directly:

```bash
.ci/ai_review/review.py path/to/patch.patch
```

This will output the review to stdout.

### Save Review to File

```bash
.ci/ai_review/review.py path/to/patch.patch --output review.txt
```

### Custom Prompt

By default, the script uses the `review-start` prompt. To use a different 
prompt:

```bash
.ci/ai_review/review.py path/to/patch.patch --prompt custom-prompt
```

(This will look for `.ci/ai_review/prompts/custom-prompt.md`)

### Advanced Options

```bash
.ci/ai_review/review.py \
  path/to/patch.patch \
  --prompt review-start \
  --model claude-sonnet-4-20250514 \
  --max-tokens 16000 \
  --output review.txt
```

### Including Additional Context

If the prompt references other scripts or files that Claude needs access to, you
can provide them as context:

```bash
.ci/ai_review/review.py path/to/patch.patch \
  --context lib/odp-util.c \
  --context utilities/checkpatch.py \
  --output review.txt
```

You can specify `--context` multiple times to include multiple files. These 
files will be included in the API call so Claude can reference them during the
review.

### Disable Git Context

By default, the script automatically extracts git context (current branch, 
recent commits, commit SHA from patch). To disable this:

```bash
.ci/ai_review/review.py path/to/patch.patch --no-git-context
```

## Command Line Options

- `patch_file` (required): Path to the patch file to review
- `--prompt PROMPT`: Name of the prompt file to use (default: review-start)
- `--model MODEL`: Claude model to use (default: claude-sonnet-4-20250514)
- `--max-tokens N`: Maximum tokens for response (default: 16000)
- `--output FILE`: Output file for the review (default: stdout)
- `--context FILE`: Additional context file to include (can be used multiple
times)
- `--no-git-context`: Disable automatic git context extraction

## Prompts

Review prompts are stored in `.ci/ai_review/prompts/` as Markdown files. The 
script will automatically load the specified prompt and combine it with the
patch content before sending to Claude.

To create a new prompt, add a new `.md` file to the prompts directory.

### Context Files for Prompts

If your prompt references scripts, tools, or specific source files that Claude 
should have access to, you have two options:

#### Option 1: Automatic Loading with @ref: (Recommended)

Add `@ref:filename` references directly in your prompt file. The script will 
automatically detect and load these files:

```markdown
<!-- In .ci/ai_review/prompts/review-start.md -->

Please review this patch according to the coding standards in @ref:CODING_STYLE.md
and compare against the reference implementation in @ref:lib/common-functions.c

When checking for memory leaks, refer to @ref:memory-patterns.md
```

The script will automatically:
- Detect all `@ref:filename` patterns in the prompt
- Load the referenced files (searches in prompts directory first, then relative
paths)
- Include them in the context sent to Claude

#### Option 2: Manual Context with --context Flag

You can also provide context files manually using the `--context` flag:

```bash
.ci/ai_review/review.py patch.patch \
  --context CODING_STYLE.md \
  --context lib/common-functions.c
```

**Note:** Both methods can be combined. Files specified with `@ref:` in prompts
will be merged with files specified via `--context` flags.

## Requirements

- Python 3.6 or later
- anthropic Python package
- Valid Anthropic API key
- Git repository (script auto-detects git root)
