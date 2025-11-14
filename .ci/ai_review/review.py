#!/usr/bin/env python3
"""
AI-powered code review script for OVS patches.

This script uses Claude (Anthropic API) to review git patches based on
prompts defined in .ci/ai_review/prompts/.
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional, List, Dict, Set

try:
    import anthropic
except ImportError:
    print("Error: anthropic package not installed.", file=sys.stderr)
    print("Please install it with: pip install anthropic", file=sys.stderr)
    sys.exit(1)


def find_git_root() -> Path:
    """Find the root of the git repository."""
    current = Path.cwd()
    while current != current.parent:
        if (current / ".git").exists():
            return current
        current = current.parent
    raise RuntimeError("Not in a git repository")


def find_referenced_files(content: str, prompts_dir: Path) -> Set[Path]:
    """
    Find all files referenced in the content using @ref:filename pattern.

    Args:
        content: The text content to scan for references
        prompts_dir: Directory where prompt files are located

    Returns:
        Set of Path objects for referenced files
    """
    # Pattern to match @ref:filename.md or @ref:path/to/file.ext
    pattern = r'@ref:([^\s\)]+)'
    matches = re.findall(pattern, content)

    referenced_files = set()
    for match in matches:
        # Try relative to prompts directory first
        ref_path = prompts_dir / match
        if ref_path.exists():
            referenced_files.add(ref_path)
        else:
            # Try as absolute or relative to git root
            ref_path = Path(match)
            if ref_path.exists():
                referenced_files.add(ref_path)
            else:
                print(f"Warning: Referenced file not found: {match}", file=sys.stderr)

    return referenced_files


def read_prompt_file(prompts_dir: Path, prompt_name: str) -> tuple[str, Set[Path]]:
    """
    Read a prompt file from the prompts directory and find referenced files.

    Args:
        prompts_dir: Directory where prompt files are located
        prompt_name: Name of the prompt (without .md extension)

    Returns:
        Tuple of (prompt_content, set_of_referenced_files)
    """
    prompt_file = prompts_dir / f"{prompt_name}.md"
    if not prompt_file.exists():
        raise FileNotFoundError(f"Prompt file not found: {prompt_file}")

    with open(prompt_file, 'r', encoding='utf-8') as f:
        content = f.read()

    # Find all referenced files
    referenced_files = find_referenced_files(content, prompts_dir)

    return content, referenced_files


def read_patch_file(patch_path: Path) -> str:
    """Read the patch file contents."""
    if not patch_path.exists():
        raise FileNotFoundError(f"Patch file not found: {patch_path}")

    with open(patch_path, 'r', encoding='utf-8') as f:
        return f.read()


def get_api_key() -> str:
    """Get the Anthropic API key from environment."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY environment variable not set.\n"
            "Please set it with: export ANTHROPIC_API_KEY='your-api-key'"
        )
    return api_key


def run_git_command(git_root: Path, command: List[str]) -> Optional[str]:
    """
    Run a git command and return its output.

    Args:
        git_root: Root of the git repository
        command: Git command as list (e.g., ['log', '--oneline', '-1'])

    Returns:
        Command output as string, or None if command fails
    """
    try:
        result = subprocess.run(
            ['git'] + command,
            cwd=git_root,
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            print(f"Git command failed: {' '.join(command)}", file=sys.stderr)
            print(f"Error: {result.stderr}", file=sys.stderr)
            return None
    except subprocess.TimeoutExpired:
        print(f"Git command timed out: {' '.join(command)}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error running git command: {e}", file=sys.stderr)
        return None


def extract_git_context(git_root: Path, patch_content: str) -> Dict[str, str]:
    """
    Extract git repository context that might be useful for the review.

    Args:
        git_root: Root of the git repository
        patch_content: The patch content (may contain commit info)

    Returns:
        Dictionary with git context information
    """
    context = {}

    # Try to extract commit SHA from patch if it's a git format-patch style
    lines = patch_content.split('\n')
    for line in lines[:50]:  # Check first 50 lines
        if line.startswith('From '):
            parts = line.split()
            if len(parts) >= 2 and len(parts[1]) >= 7:
                context['commit_sha'] = parts[1][:40]  # Full or short SHA
                break

    # Get current branch info
    branch = run_git_command(git_root, ['rev-parse', '--abbrev-ref', 'HEAD'])
    if branch:
        context['current_branch'] = branch

    # Get recent commits for context
    recent_log = run_git_command(git_root, ['log', '--oneline', '-5'])
    if recent_log:
        context['recent_commits'] = recent_log

    return context


def read_context_files(context_paths: List[Path]) -> Dict[str, str]:
    """
    Read additional context files (e.g., related source files, scripts).

    Args:
        context_paths: List of file paths to include as context

    Returns:
        Dictionary mapping file paths to their contents
    """
    context_files = {}

    for path in context_paths:
        if not path.exists():
            print(f"Warning: Context file not found: {path}", file=sys.stderr)
            continue

        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                context_files[str(path)] = content
                print(f"Loaded context file: {path}", file=sys.stderr)
        except Exception as e:
            print(f"Warning: Could not read {path}: {e}", file=sys.stderr)

    return context_files


def conduct_review(
    patch_content: str,
    prompt_content: str,
    git_context: Dict[str, str] = None,
    context_files: Dict[str, str] = None,
    model: str = "claude-sonnet-4-20250514",
    max_tokens: int = 16000
) -> str:
    """
    Conduct a code review using Claude API.

    Args:
        patch_content: The patch file content to review
        prompt_content: The review instructions/prompt
        git_context: Git repository context (commit info, branches, etc.)
        context_files: Additional context files (scripts, related sources)
        model: The Claude model to use
        max_tokens: Maximum tokens for the response

    Returns:
        The review text from Claude
    """
    api_key = get_api_key()
    client = anthropic.Anthropic(api_key=api_key)

    # Construct the full message with all context
    message_parts = [prompt_content]

    # Add git context if available
    if git_context:
        message_parts.append("\n## Git Repository Context\n")
        for key, value in git_context.items():
            message_parts.append(f"{key}: {value}\n")

    # Add context files if provided
    if context_files:
        message_parts.append("\n## Additional Context Files\n")
        for file_path, content in context_files.items():
            message_parts.append(f"\n### File: {file_path}\n")
            message_parts.append(f"```\n{content}\n```\n")

    # Add the patch to review
    message_parts.append("\n## Patch to Review\n")
    message_parts.append(patch_content)

    message_content = "".join(message_parts)

    print(f"Starting review with model: {model}", file=sys.stderr)
    print(f"Patch size: {len(patch_content)} characters", file=sys.stderr)
    if git_context:
        print(f"Git context items: {len(git_context)}", file=sys.stderr)
    if context_files:
        print(f"Context files: {len(context_files)}", file=sys.stderr)

    try:
        message = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[
                {
                    "role": "user",
                    "content": message_content
                }
            ]
        )

        # Extract the text response
        response_text = ""
        for block in message.content:
            if block.type == "text":
                response_text += block.text

        return response_text

    except anthropic.APIError as e:
        print(f"Anthropic API error: {e}", file=sys.stderr)
        raise
    except Exception as e:
        print(f"Unexpected error during review: {e}", file=sys.stderr)
        raise


def main():
    """Main entry point for the review script."""
    parser = argparse.ArgumentParser(
        description="Conduct AI-powered code review of OVS patches using Claude"
    )
    parser.add_argument(
        "patch_file",
        type=Path,
        help="Path to the patch file to review"
    )
    parser.add_argument(
        "--prompt",
        type=str,
        default="review-start",
        help="Name of the prompt to use (without .md extension). Default: review-start"
    )
    parser.add_argument(
        "--model",
        type=str,
        #default="claude-sonnet-4-20250929-v1",
        default="claude-sonnet-4-20250514",
        help="Claude model to use. Default: claude-sonnet-4-20250514"
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=16000,
        help="Maximum tokens for the response. Default: 16000"
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output file for the review (default: stdout)"
    )
    parser.add_argument(
        "--context",
        type=Path,
        action="append",
        dest="context_files",
        help="Additional context files to include (can be specified multiple times)"
    )
    parser.add_argument(
        "--no-git-context",
        action="store_true",
        help="Disable automatic git context extraction"
    )

    args = parser.parse_args()

    try:
        # Find git root and construct paths
        git_root = find_git_root()
        prompts_dir = git_root / ".ci" / "ai_review" / "prompts"

        if not prompts_dir.exists():
            print(f"Error: Prompts directory not found: {prompts_dir}", file=sys.stderr)
            sys.exit(1)

        # Read the prompt and find referenced files
        print(f"Reading prompt: {args.prompt}", file=sys.stderr)
        prompt_content, referenced_files = read_prompt_file(prompts_dir, args.prompt)

        if referenced_files:
            print(f"Found {len(referenced_files)} referenced file(s) in prompt:", file=sys.stderr)
            for ref_file in referenced_files:
                print(f"  - {ref_file}", file=sys.stderr)

        print(f"Reading patch: {args.patch_file}", file=sys.stderr)
        patch_content = read_patch_file(args.patch_file)

        # Extract git context unless disabled
        git_context = None
        if not args.no_git_context:
            print("Extracting git context...", file=sys.stderr)
            git_context = extract_git_context(git_root, patch_content)

        # Merge referenced files with explicitly provided context files
        all_context_paths = list(referenced_files)
        if args.context_files:
            all_context_paths.extend(args.context_files)

        # Read all context files
        context_files = None
        if all_context_paths:
            print(f"Loading {len(all_context_paths)} total context file(s)...", file=sys.stderr)
            context_files = read_context_files(all_context_paths)

        # Conduct the review
        review_result = conduct_review(
            patch_content=patch_content,
            prompt_content=prompt_content,
            git_context=git_context,
            context_files=context_files,
            model=args.model,
            max_tokens=args.max_tokens
        )

        # Output the result
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(review_result)
            print(f"Review written to: {args.output}", file=sys.stderr)
        else:
            print(review_result)

        print("\nReview completed successfully!", file=sys.stderr)

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nReview interrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
