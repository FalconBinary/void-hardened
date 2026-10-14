# vim: set ts=4 sw=4 et:
# void-hardened: огромные страницы (THP) — режим madvise (по умолчанию в ядре Void):
# получают только программы, которые просят (Firefox, mesa). defer+madvise — уплотнение
# памяти для них идёт в фоне (kcompactd), а не в момент выделения: нет задержек
# на page fault. Как в CachyOS (docs/11, docs/15).
[ -w /sys/kernel/mm/transparent_hugepage/defrag ] && \
    echo defer+madvise > /sys/kernel/mm/transparent_hugepage/defrag
