# Rudin Assistant - :hammer: developer mode


## TODO

---
- [ ] Montoya API 로 변경 필요
- [x] config에 내용이 없을 경우, 자동으로 생성하는 코드 추가
- [x] Menu에 Config Update, Extension Setting 초기화 추가
- [ ] XSS Filter 요약, 세부 연동 시켜야함
- [ ] 디렉토리 리스팅 개발: Apache, Tomcat, Nginx 등에서 사용하는 기본 파일, 폴더 접근 테스트
- [ ] 정보 노출: 서버 버전 정보, 에러 정보 추가
- [ ] 정보 노출: Request 도 검사
- [ ] Fuzzing: 각 페이지 별로 go/pass, 기본 파라미터 및 Json 파라미터 호환


## 빌드 환경

---
- OpenJDK 21.0.1
- Burp Extender API v2.3
- Burp Community Edition v2023.11.1.x
- VScode, Intelij


## 빌드 방법

---
```cmd
# 터미널 > ./gradlew build rusistBuild
OR
# Intellj -> 실행 -> 구성 편집 -> gradle -> build rusistBuild
```

깃 레포지토리 클론을 제일 먼저 합니다.

```cmd
git clone git@github.com:rudin-kr/Burp_RudinAssistTools.git
```

rusistBuild 활용해서 jar 생성하도록 세팅해 줍니다. ($buildpath/build/libs 아래에 저장됨)
![세팅 확인](https://user-images.githubusercontent.com/42140558/165305203-f73bc8c7-bdd5-494e-9f9a-88fb2091a759.png)

빌드 후 생성된 jar 파일을 Burp에 로딩 합니다.
![짜르 로딩](https://user-images.githubusercontent.com/42140558/165305698-44b6f53e-c640-442a-a92b-c2d550421475.png)
