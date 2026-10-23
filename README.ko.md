# php2shell-guard

[English](README.md) | [한국어](README.ko.md)

**php2shell**(CVE-2026-109618 / CVE-2026-109619)을 찾고, 임시로 막고, 다시 들어오지 않게 지키는 도구입니다. 두 취약점은 PHP 원격 코드 실행 버그이고 2026년 10월 17일부터 실제 공격에 쓰이고 있습니다. bash 스크립트 하나와 PHP 파일 하나로 되어 있어 설치가 필요 없습니다. 공격 코드는 들어 있지 않습니다.

> **PHP를 8.5.12, 8.4.27, 8.3.36, 8.2.35 이상으로 올리세요** ([PHP 공지](https://www.php.net/archive/2026.php#2026-10-21-5)). 배포판 패키지는 버전 번호를 바꾸지 않고 수정만 넣기도 합니다. 7.4부터 8.1까지는 벤더 패키지나 PHP가 공개한 소스 백포트([7.4](https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619), [8.0](https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619), [8.1](https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619))를 쓰고, 그보다 오래된 버전은 수정이 없습니다. 이 저장소의 모든 조치는 패치 전까지 버티는 임시 조치입니다.

## 사용법

```bash
git clone https://github.com/Blue-B/php2shell-guard && cd php2shell-guard
sudo ./guard.sh scan            # 영향받는지 확인
sudo ./guard.sh fix             # 임시 조치로 무엇이 바뀌는지 미리 보기
sudo ./guard.sh fix --apply     # 적용하고 설정을 검사한 뒤 PHP를 다시 읽기
```

| 명령 | 하는 일 |
|---|---|
| `guard.sh scan` | 서버의 모든 PHP(패널, 컨테이너 포함)를 찾아 패치 여부, 배포판 백포트, 임시 설정 상태를 알려줍니다 |
| `guard.sh fix [--apply]` | 패치 안 된 PHP에만 임시 조치를 합니다. `--apply`가 없으면 계획만 보여줍니다. 붙이면 새 설정 파일만 추가하고(기존 설정은 건드리지 않음), `php -r`, `php-fpm -t`, `apachectl -t` 결과가 달라지면 되돌린 뒤, systemd 환경이면 PHP를 다시 읽게 합니다 |
| `guard.sh undo` | 패치 후 그 파일들을 지웁니다(이 도구의 표시가 있는 파일만) |
| `guard.sh images [DIR...]` | Dockerfile, compose, 쿠버네티스 파일에서 PHP 이미지 태그를 찾습니다. 패치 안 된 태그나 지원 끝난 버전이 있으면 종료 코드 1이라 CI에서 막는 용도로 씁니다 |
| `guard.sh webcheck WEBROOT` | 웹으로 실제 돌고 있는 PHP 설정을 보여주는 `check.php`를 설치합니다. 확인 후 지우세요 |
| `guard.sh test URL` | 해롭지 않은 multipart 요청을 여러 형태로 보내 앞단 차단 규칙이 막는지 확인합니다 |
| `guard.sh hunt [WEBROOT...]` | 10월 17일 이후 침해 흔적을 찾습니다. PHP 아래에서 뜬 셸, 워커 크래시, 스크립트 실행 전 메모리 부족, 웹셸, cron |

`scan`, `test`, `hunt`, `images`는 `--json`을 붙이면 JSON 하나를 출력합니다(SIEM이나 스크립트용). 종료 코드 1은 확인할 게 있다는 뜻입니다.

## 영향 확인

| 운영 환경 | 확인 방법 | 조치 |
|---|---|---|
| Debian/Ubuntu, RHEL 패키지 | `guard.sh scan` (패키지 변경 기록을 읽어서 백포트도 인정) | 패키지 업그레이드 |
| 공식 `php` Docker 이미지, 소스 빌드 | `guard.sh images .`, `guard.sh scan` | 수정된 태그로 다시 빌드 |
| cPanel, Plesk, aaPanel, CloudLinux alt-php | `guard.sh scan` (패널 경로 포함) | 패널의 PHP 업데이트 기능 |
| 공유 호스팅 | `guard.sh webcheck` 또는 호스팅 업체에 문의 | 업체에 패치 요청, 업로드가 없으면 앞단 차단 규칙 |
| Windows / IIS | `check.php` | 패치. IIS용 차단 규칙은 아직 없음 |

## 임시 조치

| 사이트 상황 | 할 일 |
|---|---|
| 업로드나 multipart 폼이 없음 | `rules/`에서 웹서버에 맞는 규칙으로 multipart POST를 앞단에서 막고, `guard.sh fix --apply`(또는 `rules/php.ini` 직접 적용) |
| 업로드가 필요함 | `guard.sh fix --apply`, 또는 `rules/php.ini`를 php.ini, FPM pool, vhost에 적용. 업로드 경로만 허용하고 믿을 수 있는 사용자로 제한 |
| 둘 다 불가능 | 패치할 때까지 사이트를 인터넷에서 내리기 |

- FPM, CGI, LSAPI에서는 `.user.ini`와 `ini_set()`이 너무 늦게 적용되어 **효과가 없습니다**. 바꾼 뒤에는 PHP 워커를 모두 재시작하고 `guard.sh webcheck`로 확인하세요.
- `memory_limit=-1`은 CVE-2026-109618에 대한 PHP의 임시 권고입니다. 대신 서비스 전체 메모리를 제한하고(systemd `MemoryMax=`, 컨테이너 메모리 제한), 패치 후 `guard.sh undo`로 되돌리세요.
- multipart를 막으면 업로드와 multipart 폼이 동작하지 않습니다. 허용 목록에 넣은 경로는 계속 노출됩니다.

## 재발 방지

누군가 오래된 PHP 이미지를 고정하면 CI를 실패시키기:

```yaml
# .github/workflows/php2shell.yml
on: [push, pull_request]
jobs:
  php-image-tags:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: git clone --depth 1 --branch v0.3.0 https://github.com/Blue-B/php2shell-guard /tmp/p2sg && /tmp/p2sg/guard.sh images .
```

서버를 매일 다시 점검해서 롤백이나 잊힌 컨테이너를 잡기:

```bash
# /etc/cron.d/php2shell-guard
17 6 * * * root /opt/php2shell-guard/guard.sh scan --json >> /var/log/php2shell-guard.jsonl 2>/dev/null
```

## 테스트

`tests/run.sh`(Docker 필요)는 모든 명령을 실제 서버에 대고 돌립니다. Apache/LiteSpeed, Nginx, Caddy, HAProxy, ModSecurity 차단 규칙, FPM과 mod_php에서의 `check.php`, 심어 둔 흔적을 찾는 `scan`/`hunt`, Nginx 뒤 공식 FPM 이미지와 Ubuntu 패키지에서의 `fix`/`undo`까지 확인합니다. Cloudflare 규칙은 테스트하지 않았습니다.

## 한계

- 임시 조치는 어떤 애플리케이션에나 통하는 공격 경로만 막습니다. 애플리케이션을 거쳐 닿는 버그는 패치 전까지 남아 있습니다.
- `fix`는 systemd 환경에서만 PHP를 직접 다시 읽게 합니다. 컨테이너, 패널, LiteSpeed는 직접 재시작해야 합니다. FPM pool 설정을 다시 만드는 패널은 이 도구가 추가한 pool 파일을 지울 수 있습니다.
- `images`는 `ARG`나 환경 변수로 정한 태그를 풀어 보지 않습니다.
- `test`는 지정한 URL만 확인합니다. `hunt`는 1차 분류용이지 포렌식 도구가 아닙니다.
- Linux와 Bash 4 이상. `check.php`는 Windows에서도 동작합니다.

## 라이선스

MIT
