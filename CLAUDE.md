# mirage-oss — рабочий контракт репозитория

## Что это

`mirage-oss` — **OSS-слой Mirage**: глубокие библиотеки (криптография,
идентичности, wire-протокол, mux, host-security, периметр), вынесенные из
репозитория флота `mirage2web` в отдельный самостоятельный репозиторий.

Здесь **нет флотового mesh-кода**. Флот (mesh-крейты, кворум, secd, warden)
остаётся в репозитории флота и берёт библиотеки **отсюда**.

## Состав workspace

Один Cargo-workspace, 18 крейтов в `crates/`. Четыре из них
(`mirage-blindtoken`, `mirage-ringmember`, `mirage-hostsec`,
`mirage-perimeter`) держат свой `publish = false` и на crates.io не идут,
даже когда у воркспейса публикация включена.

| Крейт | Что это |
|---|---|
| `mirage-ids` | типизированные идентификаторы (machine / mesh / node / epoch …) |
| `mirage-blindtoken` | RFC 9474 blind token (RSABSSA-SHA384-PSS-Randomized) |
| `mirage-ringmember` | Merkle ring-membership credential (scheme 0x04) |
| `mirage-core` | ядро: крипто, identity, capsule, конфиг, наблюдения периметра |
| `mirage-protocol` | wire-протокол, транспорт, камуфляж, авторизация |
| `mirage-mux` | mux-слой кадров |
| `mirage-dial-core` | пакет `mirage-control-plane` — control-plane схема/диал |
| `mirage-wire-http-client` | HTTP поверх wire для не-opbox процессов |
| `mirage-shared-types` | общие типы между воркерами (клиентский конфиг и пр.) |
| `mirage-hostsec` | рецепты host-security (hardening, nftables, posture) |
| `mirage-perimeter` | периметр: классификация входа, отказ не-wire |
| `mirage-node` | data plane библиотекой: runtime, слушатели, splice, exit. Без флота |
| `mirage-subscriber-gate` | проверка диала клиента и разбор туннеля |
| `mirage-vpn` | сессия клиент–терминатор, без луковицы |
| `mirage-vpn-mesh` | та же сессия внутри луковичной цепочки |
| `mirage-vpn-cli` | программа вокруг сессии: конфиг, слушатели, connect |
| `mirage-chain-leg` | нога цепочки: завести сессию и вывести на выходе |
| `mirage-standalone` | программа сервера `m1r4g3-server`: ключи, `client.link`, свой выход |

## Правило зависимостей — строго сверху вниз

```
m1r4g3-server (этот репозиторий)  ->  библиотеки mirage-oss
флот (mirage-mesh)                ->  библиотеки mirage-oss
```

* Флот **берёт** библиотеки отсюда (path- или git-зависимость).
* Флот **не заходит** в этот репозиторий: ни крейта, ни ветки, ни feature-флага.
* Внутри репозитория зависимости идут только по направлению «снизу вверх»:
  `mirage-ids` → `mirage-core` → `mirage-protocol` → `mirage-control-plane` /
  `mirage-wire-http-client`; `mirage-perimeter` — на `mirage-protocol`,
  `mirage-hostsec`, `mirage-core`.

## Запрет на mesh-крейты

В этот репозиторий **не переносить** и **не возвращать**:

`mesh-core`, `mesh-gossip`, `mesh-storage`, `mesh-quarantine`,
`mirage-mesh`, `mirage-mesh-client`, `mirage-mesh-wire`,
`mirage-quorum`, `mirage-secd`, `mirage-warden`.

Если фиче из этого списка понадобится «глубокой» библиотеке — она
переносится в `mirage-oss` **без** её собственной mesh-логики, а не
вместе с ней. Тянуть флот внутрь — запрещено.

## Обратная совместимость не требуется — важна изоляция

Этот репозиторий не обязан сохранять API флота. Приоритет: **изоляция
слоёв**, а не совместимость сигнатур. Если публичный API глубокой
библиотеки удобнее поменять ради чистоты слоя — меняем, и описываем
изменение. Совместимость держится на стороне флота (адаптеры там).

## Сервер живёт здесь

`m1r4g3-server` — крейт `crates/mirage-standalone` этого репозитория.
Образ собирается из корня: `scripts/build-image.ps1`. Отдельного
репозитория сервера нет.

## Правила работы

* Сборка и тесты: `cargo build --workspace`, `cargo test --workspace`
  (должны быть зелёными; счётчики — в отчёте).
* `Cargo.lock` коммитится (в репозитории есть точные пины внешних
  зависимостей — см. `mirage-core`'s `flate2` / `miniz_oxide`).
* Одна задача — один коммит; пути кладём в индекс явно, без `git add .`.
* Публикация в crates.io и push в remote — только по команде владельца
  через скрипты `nemo/CICD/`.

## Тесты: известная шероховатость Windows

`.cargo/config.toml` ограничивает параллелизм libtest
(`RUST_TEST_THREADS = "4"`) — UDP-тесты камуфляжа в `mirage-protocol`
(`camouflage/raw_udp.rs`, `camouflage/wireguard.rs`) ждут анонс сессии по
одному UDP-датаграмму **без таймаута**, и потерянный датаграмм оставляет
тест ждать вечно — прогон зависает, а не падает.

Два теста-близнеца
(`an_actively_sending_peer_survives_a_spray_many_times_larger_than_the_whole_map`
в `raw_udp.rs` и в `wireguard.rs`) поэтому помечены
`#[cfg_attr(windows, ignore = ...)]`: на Windows они пропускаются, на Linux
(платформа флота) — работают как раньше. Код этих тестов побайтово совпадает
с флотовым, то есть шероховатость унаследована, а не внесена здесь; настоящее
лечение (ограниченные await'ы) — в флоте.

Запуск изнутри репозитория подхватывает `.cargo/config.toml` сам; при запуске
снаружи добавь `--config .cargo/config.toml`.
