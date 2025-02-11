package openaitest.jwt_02;

import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class Jwt02ApplicationTests {

    @Value("${custom.jwt.secretKey}")
    private String secretKeyPlain;
    @Autowired
    private JwtProvider jwtProvider;


    @Test
    @DisplayName("secretKey가 존재해야 함")
    void t1() {
        assertThat(secretKeyPlain).isNotNull();
    }

    @Test
    @DisplayName("secretKey 원문으로 hmac 암호화 알고리즘에 맞는 SecretKey 객체를 만들 수 있다.")
    void t2() {
        // 키를 base64 인코딩 한다
        String keyBase64Encoded = Base64.getEncoder().encodeToString(secretKeyPlain.getBytes());

        // base64 인코딩 된 키를 이용해서 SecretKey 객체를 만든다.
        SecretKey secretKey = Keys.hmacShaKeyFor(keyBase64Encoded.getBytes());

        assertThat(secretKey).isNotNull();
    }

    @Test
    @DisplayName("JwtProvider 객체로 SecretKey 객체 생성")
    void t3() {
        SecretKey secretKey = jwtProvider.getSecretKey();

        assertThat(secretKey).isNotNull();
    }

    @Test
    @DisplayName("SecretKey 객체는 단 한번만 생성 되어야 함")
    void t4() {
        SecretKey secretKey1 = jwtProvider.getSecretKey();
        SecretKey secretKey2 = jwtProvider.getSecretKey();

        assertThat(secretKey1 == secretKey2).isTrue();
    }

    @Test
    @DisplayName("accessToken 얻기")
    void t5() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", 1L);
        claims.put("username", "admin");

        // 현재시각으로부터 5시간의 유효기간을 가지는 토큰 생성
        String accessToken = jwtProvider.genToken(claims, 60 * 60 * 5);

        System.out.println("accessToken: " + accessToken);

        assertThat(accessToken).isNotNull();
    }

    @Test
    @DisplayName("accessToken은 만료가 되면 유효하지 않다")
    void t6() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", 1L);
        claims.put("username", "admin");

        String accessToken = jwtProvider.genToken(claims, -1);

        System.out.println("accessToken: " + accessToken);

        assertThat(jwtProvider.verify(accessToken)).isFalse();
    }

    @Test
    @DisplayName("accessToken을 통해서 claims를 얻을 수 있다")
    void t7() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", 1L);
        claims.put("username", "admin");

        String accessToken = jwtProvider.genToken(claims, 60 * 60 * 5);

        System.out.println("accessToken: " + accessToken);

        assertThat(jwtProvider.verify(accessToken)).isTrue();

        Map<String, Object> claimsFromToken = jwtProvider.getClaims(accessToken);

        System.out.println("claimsFromToken: " + claimsFromToken);
    }
}
