# php2shell-guard

[English](README.md) | [한국어](README.ko.md)

서버가 **php2shell**(CVE-2026-109618 / CVE-2026-109619)에 노출됐는지 검사하고, 패치 전까지 막아 주는 도구입니다. 두 취약점은 PHP 원격 코드 실행 버그이고 2026년 10월 17일부터 공격 시도가 확인됐습니다([Amazon](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/)). bash 스크립트 하나라 설치가 필요 없고, 공격 코드는 들어 있지 않습니다.

수정된 버전은 **PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35**입니다([PHP 공지](https://www.php.net/archive/2026.php#2026-10-21-5)). 7.4부터 8.1까지는 벤더 패키지나 PHP의 소스 백포트([7.4](https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619), [8.0](https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619), [8.1](https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619))를 쓰고, 그보다 오래된 버전은 수정이 없습니다.

## 사용법

```bash
git clone https://github.com/Blue-B/php2shell-guard && cd php2shell-guard

sudo ./guard.sh scan           # 1. 취약한지 검사
sudo ./guard.sh fix --apply    # 2. 지금 바로 막기 (임시)
                               # 3. PHP 업데이트 (fix가 내 서버에 맞는 명령을 알려줌)
sudo ./guard.sh undo           # 4. 업데이트 후 임시 설정 되돌리기
```

1. **scan**은 서버의 모든 PHP(관리 패널, Docker 컨테이너 포함)를 찾아 패치됐는지 알려줍니다. 버전 번호는 그대로인데 수정만 들어간 배포판 패키지도 패치된 것으로 보지만, 두 CVE가 모두 적혀 있을 때만 그렇게 봅니다. 업데이트 후 재시작하지 않아 아직 예전 코드로 돌고 있는 PHP 프로세스도 찾아냅니다.
2. **fix --apply**는 PHP가 권고한 임시 설정을 넣고, 설정이 정상인지 검사한 뒤 PHP를 다시 읽게 합니다. 자기 파일만 새로 추가하고 기존 설정은 건드리지 않습니다. `--apply` 없이 `fix`만 치면 무엇을 바꿀지 보여주기만 합니다. Docker나 관리 패널 환경에서는 PHP를 직접 재시작하세요.
3. **PHP 업데이트**가 진짜 해결이고, 직접 실행해야 합니다. `fix`가 마지막에 내 서버에 맞는 방법(`apt`, `dnf`, 새 Docker 태그, 패널 업데이트)을 알려줍니다.
4. **undo**로 임시 설정을 지웁니다. 임시 설정 중 하나가 PHP 메모리 제한을 풀기 때문에, 업데이트 후에는 꼭 되돌리세요.

```text
$ sudo ./guard.sh scan
== PHP binaries on this host ==
  /usr/local/sbin/php-fpm
  [!!] PHP 8.3.35: below fixed release 8.3.36 (unless a distro package backported the fix)
```

## 다른 명령

| 명령 | 하는 일 |
|---|---|
| `guard.sh check URL` | 서버 접속 없이 밖에서, 사이트가 알려주는 PHP 버전을 읽습니다. 배포판 빌드나 버전을 숨긴 사이트는 안전하다거나 취약하다고 단정하지 않고 확인 불가로 알려줍니다 |
| `guard.sh images [DIR]` | Dockerfile, compose, 쿠버네티스 파일에서 오래된 PHP 이미지 태그를 찾습니다. 패치 안 된 태그가 있으면 종료 코드 1이라 CI에서 막을 수 있습니다 |
| `guard.sh hunt` | 이미 해킹당한 흔적을 찾습니다. PHP가 띄운 셸, 크래시, 웹셸, cron |
| `guard.sh webcheck WEBROOT` | 웹사이트가 실제로 쓰는 설정을 보여주는 `check.php`를 설치합니다. 확인 후 지우세요 |
| `guard.sh test URL` | `rules/`의 웹서버 차단 규칙이 공격 입구를 막는지 확인합니다 |

`scan`, `check`, `hunt`, `images`, `test`는 `--json`을 붙이면 JSON으로 출력합니다.

**사이트에 파일 업로드가 없다면** `rules/`에서 웹서버에 맞는 규칙(Apache, Nginx, Caddy, HAProxy, ModSecurity, Cloudflare)으로 multipart POST도 막으세요. 업로드가 막히기 때문에 자동으로 넣지 않습니다.

**오래된 이미지가 다시 들어오지 않게** GitHub Actions에 한 단계 추가(`path`는 생략 가능, 기본값 `.`):

```yaml
- uses: actions/checkout@v4
- uses: Blue-B/php2shell-guard@v0
  with:
    path: docker k8s
```

다른 CI: `git clone --depth 1 --branch v0 https://github.com/Blue-B/php2shell-guard /tmp/p2sg && /tmp/p2sg/guard.sh images .`

`v0`는 항상 최신 0.x 릴리스를 가리키므로, CI 설정을 고치지 않아도 새 수정이 반영됩니다. 고정하고 싶으면 `v0.4.0`처럼 정확한 태그를 쓰세요.

## openai/php2shell-checker와 비교

[php2shell-checker](https://github.com/openai/php2shell-checker)는 버전 번호로 영향받을 수 있는지 알려줍니다. php2shell-guard는 거기에 더해 패치 전까지 공격을 막고, 이미 당했는지 흔적도 찾습니다.

| | php2shell-guard | php2shell-checker |
|---|---|---|
| URL로 사이트 확인 | `check` | 있음 |
| 서버 확인 | `scan` 스크립트: 모든 PHP 빌드, 컨테이너, 패널, 배포판 백포트, 재시작 안 된 프로세스 | Codex 에이전트용 안내문 |
| 패치 전까지 막기 | `fix --apply`(PHP 설정), 웹서버 6종 차단 규칙(테스트 완료) | 없음 |
| 해킹 흔적 찾기 | `hunt` | 없음 |
| CI에서 오래된 PHP 이미지 막기 | `images`, GitHub Action | 없음 |
| 필요한 것 | bash, curl | Node.js 또는 Codex |

## 한계

- 임시 설정은 어떤 PHP 사이트에나 통하는 공격만 막습니다. 내 애플리케이션 코드를 거치는 공격은 PHP를 업데이트할 때까지 가능합니다.
- `hunt`는 1차 확인용이지 포렌식 도구가 아닙니다. `images`는 `ARG`로 정한 태그를 풀어 보지 않습니다. `check`는 사이트가 헤더로 알려주는 것만 봅니다.
- Linux와 Bash 4 이상. `check.php`는 Windows에서도 동작합니다.
- `tests/run.sh`(Docker 필요)가 모든 명령과 규칙을 실제 서버로 테스트합니다. Cloudflare 규칙은 테스트하지 않았습니다.

## 라이선스

MIT
