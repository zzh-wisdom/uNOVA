git log --format='%aN' | sort -u | while read name; do \
    printf "[%-10s] " $name; \
    git log --author="$name" --pretty=tformat: --numstat | \
    grep -E "(.cpp|.cc|.h|.txt|Makefile|.md)$" | \
    awk '{ add += $1; subs += $2; loc += $1 - $2 } END { printf "added lines: %6s, removed lines: %6s, total lines: %6s\n", add, subs, loc }' -; \
done

printf "[%-10s] " "total"
git log --pretty=tformat: --numstat | \
grep -E "(.cpp|.cc|.h|.txt|Makefile|.md)$" | \
awk '{ add += $1; subs += $2; loc += $1 - $2 } END { printf "added lines: %6s, removed lines: %6s, total lines: %6s\n", add, subs, loc }' -
