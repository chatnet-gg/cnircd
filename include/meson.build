setup_h = configure_file(
  output: 'setup.h',
  configuration: conf_data,
  install: false
)

serno_h = vcs_tag(
  # In a git checkout the version comes from git. A source archive (git archive, GitHub's "Download") has no .git, but
  # git writes the commit into VERSION_INFO there (export-subst); an unexpanded "$Format:" line means "ask git".
  command: ['sh', '-c', 'l=$(sed -n 1p "$1" 2>/dev/null); case "$l" in ""|*Format:*) git rev-list -1 --no-commit-header --date=format:%Y%m%d --format=%cd-%h HEAD;; *) echo "$l" | awk \'{gsub("-","",$1); print $1 "-" $2}\';; esac', 'sh', meson.project_source_root() / 'VERSION_INFO'],
  input: 'serno.h.in',
  output: 'serno.h',
  replace_string: '@SERNO@',
  fallback: 'unknown',
)

datecode_h = vcs_tag(
  command: ['sh', '-c', 'l=$(sed -n 2p "$1" 2>/dev/null); case "$l" in ""|*Format:*) git rev-list -1 --no-commit-header --format=%ct HEAD;; *) echo "$l";; esac', 'sh', meson.project_source_root() / 'VERSION_INFO'],
  input: 'datecode.h.in',
  output: 'datecode.h',
  replace_string: '@DATECODE@',
  fallback: '0',
)

global_include_dep = declare_dependency(
  sources: [setup_h, serno_h, datecode_h],
  include_directories: include_directories('.'),
)
