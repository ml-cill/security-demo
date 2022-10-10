# SpringSecurity Demo

> SpringBoot： 2.7.3  
> SpringSecurity： 2.7.3


### debug 探究运行机制

security 的过滤链路（16）：

![security默认过滤链路](./img/2022-09-08%20222124.png)

其中有3个是我们需要关注的（在这几个过滤器中，我们可以把自己的逻辑插入进去），分别是

- UsernamePasswordAuthenticationFilter： 校验用户名密码是否正确
- ExceptionTranslationFilter： 处理前面的几个链接器 如果出现问题就不允许登录
- FilterSecurityInterceptor： 权限校验拦截器

**用户名与密码校验的过滤器源码分析（UsernamePasswordAuthenticationFilter）**

1. `UsernamePasswordAuthenticationFilter.attemptAuthentication()`
2. `ProviderManager.authenticate()` 
3. `DaoAuthenticationProvider.retrieveUser()` 
4. `InMemoryUserDetailsManage.loadUserByUsername()`

- `loadUserByUsername()`
    - 根据 username 获取系统用户的登录以及授权信息
    - Inmemory在默认内存中存储了相应的用户信息
- `retrieveUser()`
    - 对比表单中的密码与系统用户密码是否一致
    - createSuccessAuthentication 添加权限信息设置到 Authentication
- `authenticate()`
    - 接受完全体 Authentication
- 验证结束之后
    - SecurityContextHolder.setContext(context);

### 自定义登录

jwt + mysql + myBatisPlus + Redis;

核心思路是自定义`UserDetailManager`来替换掉`InMemoryUserDetailsManage`  
由原本的从内存中获取User用户信息转变为从数据库中查询用户信息，并对信息进行比对  

#### JJWT java JWT

- pom依赖
  ```xml
  <dependency>
      <groupId>io.jsonwebtoken</groupId>
      <artifactId>jjwt</artifactId>
      <version>0.9.0</version>
  </dependency>
  ```
- 加解密
  ```java
  @Test
  void jwtEncryptAndDecodeTest() {
      // 设置 jwt 加密
      String jwt = Jwts.builder()
              .setId("Security-DEMO") // 设置id
              .setSubject("Security") // 设置主题
              .setIssuedAt(new Date()) // 签发日期
              // .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60))  // 设置过期时间
              .claim("userId", "123")
              .signWith(SignatureAlgorithm.HS256, "melii").compact(); // 加密模式一个盐值
      System.out.println(jwt);
  
      // 设置 jwt 解密
      Claims claims = Jwts.parser()
              .setSigningKey("melii")
              .parseClaimsJws(jwt)
              .getBody();
      System.out.println(claims);
  }
  ```

#### JWT & Redis 工具类

- FastJsonRedisSerializer
- RedisConfig
- JwtUtil

#### 自定义用户服务

security中默认的用户登录校验是通过 `UserDetailsManager` 的实现 `InMemoryUserDetailsManager`  来进行处理得的，我们只需要按照个人的规则重新实现 `UserDetailsManager` 就可以替换掉默认的用户校验。

- 用户数据表实现

  ```sql
  CREATE TABLE `sys_user` (
  `id` BIGINT ( 20 ) NOT NULL AUTO_INCREMENT COMMENT '主键',
  `user_name` VARCHAR ( 64 ) COLLATE utf8mb4_bin NOT NULL DEFAULT 'NULL' COMMENT '用户名',
  `nick_name` VARCHAR ( 64 ) COLLATE utf8mb4_bin NOT NULL DEFAULT 'NULL' COMMENT '昵称',
  `password` VARCHAR ( 64 ) COLLATE utf8mb4_bin NOT NULL DEFAULT 'NULL' COMMENT '密码',
  `status` CHAR ( 1 ) COLLATE utf8mb4_bin DEFAULT '0' COMMENT '账号状态（0正常 1停用）',
  `email` VARCHAR ( 64 ) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '邮箱',
  `phonenumber` VARCHAR ( 32 ) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '手机号',
  `sex` CHAR ( 1 ) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '用户性别（0男，1女，2未知）',
  `avatar` VARCHAR ( 128 ) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '头像',
  `user_type` CHAR ( 1 ) COLLATE utf8mb4_bin NOT NULL DEFAULT '1' COMMENT '用户类型（0管理员，1普通用户）',
  `create_by` BIGINT ( 20 ) DEFAULT NULL COMMENT '创建人的用户id',
  `create_time` datetime NOT NULL COMMENT '创建时间',
  `update_by` BIGINT ( 20 ) DEFAULT NULL COMMENT '更新人',
  `update_time` datetime DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  `del_flag` INT ( 11 ) DEFAULT '0' COMMENT '删除标志（0代表未删除，1代表已删除）',
  PRIMARY KEY ( `id` ) 
  ) ENGINE = INNODB AUTO_INCREMENT = 3 DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_bin;
  ```

- `mybatis`、`mysql`依赖以及 `mybatis` 、`mysql`配置信息  **略**

- 重写 `UserDetailsService`

  ```java
  @Service
  public class CustomUserDetailsManager implements UserDetailsService {
  
      @Autowired
      private UserMapper userMapper;
  
      /**
       * 通过用户名进行登录
       * @param username
       * @return
       * @throws UsernameNotFoundException
       */
      @Override
      public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
          // 根据用户名获取用户信息
          LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
          wrapper.eq(User::getUserName, username);
          User user = userMapper.selectOne(wrapper);
  
          // 如果查询不到数据就通过抛出异常来给出提示
          if (Objects.isNull(user)) {
              throw new UsernameNotFoundException(username);
          } else {
              // TODO: 2022/9/12 根据用户查询权限信息，并添加到 loginUser 对象中
  
              // 封装成UserDetails对象返回
              return new LoginUser(user);
          }
      }
  }
  ```
  
- 自定义登录接口
  - security 配置文件新增
    ```java
    @Configuration
    public class SecurityConfig {
    
      @Bean
      public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
      }
    
    
      /*
      * 原本继承 WebSecurityConfigurerAdapter 在2.7 的版本已经不推荐使用了
      *
      * 现在的写法是 自定义一个 SecurityFilterChain
      * */
  
      @Bean
      public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
          /*
          * 关闭 csrf(跨站请求伪造)
          * 不通过 session 获取 securityContext
          * 设置 /user/login 匿名接口
          */
          http.csrf().disable()
                  .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                  .authorizeRequests()
                  .antMatchers("/user/login").anonymous()
                  .anyRequest().authenticated();
          return http.build();
      }
  
      @Autowired
      private AuthenticationConfiguration authenticationConfiguration;
  
      @Bean
      public AuthenticationManager authenticationConfiguration() throws Exception {
          AuthenticationManager authenticationManager = authenticationConfiguration.getAuthenticationManager();
          return authenticationManager;
      }
    }

    ```
  - 登录接口实现详情
    ```java
    @Service
    public class LoginServiceImpl implements LoginService {
    
    
        @Autowired
        private AuthenticationManager authenticationManager;
    
        @Autowired
        private RedisCacheUtil redisCacheUtil;
    
        @Override
        public ResponseResult login(User user) {
            // 使用 ProviderManager(AuthenticationManager的实现) auth 方法进行验证
            Authentication authenticate = authenticationManager.authenticate(
                    UsernamePasswordAuthenticationToken.unauthenticated(user.getUserName(), user.getPassword()));
            // 校验失败的情况下 需要返回错误信息
            if (Objects.isNull(authenticate)) {
                throw new RuntimeException("用户名或密码错误");
            }
    
            // 自己生成 JWT 给前端
            LoginUser loginUser = (LoginUser) authenticate.getPrincipal();
            String userId = loginUser.getUser().getId().toString();
            String jwt = JwtUtil.createJWT(userId);
    
            // 系统用户相关信息存放到redis中
            redisCacheUtil.setCacheObject("user:"+userId, loginUser);
    
            // 确定返回值内容
            Map resultDateMap = new HashMap<String, String>();
            resultDateMap.put("jwt", jwt);
            return new ResponseResult(200, "登录成功", resultDateMap);
        }
    }
    ```
    - 
- 设置认证过滤器
  - 过滤器自定义
    ```java
    /**
     * 认证过滤器
     * <p>
     * 继承 OncePerRequestFilter ， 为了请求前此过滤器只走一次
     *
     * @author: melii ma
     * @date: 2022/9/15 22:29
     */
    @Component
    public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Autowired
    RedisCacheUtil redisCacheUtil;
  
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 1. 获取 Token
        String token = request.getHeader("token");
        if (!StringUtils.hasText(token)) {
          // 未登录的情况下 放行，让后面的过滤器来执行
          filterChain.doFilter(request, response);
          return;
        }

        // 2. 解析 Token
        Claims claims;
        try {
            claims = JwtUtil.parseJWT(token);
        } catch (Exception e) {
            throw new RuntimeException("token 不合法");
        }
 
        // 3. 获取 userId，并从redis 中获取用户信息
        String userId = claims.getSubject();
        LoginUser loginUser = redisCacheUtil.getCacheObject("user:" + userId);
        if (Objects.isNull(loginUser)) {
            throw new RuntimeException("当前用户未登录");
        }
 
        // 4. 封装 Authentication 并存入 SecurityContextHolder
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(
                        loginUser, null,null));
 
        filterChain.doFilter(request, response);
      }
    }
    ```
  - 将认证过滤器添加到 security 中
    ```java
    // 将自定义认证过滤器放到 UsernamePasswordAuthenticationFilter 过滤器之前执行
    http.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
    ```
- 登出接口
  - 新增接口
    ```java
    @Override
    public ResponseResult logout() {
        // 获取到 Token, 删除 redis 中的数据
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        redisCacheUtil.deleteObject("user:"+loginUser.getUser().getId());
        return new ResponseResult(200, "退出成功");
    }
    ```

- 加密规则修改
  - 加密配置
    ```java
    /**
     * 自定义加密模式
     *
     * security 中默认使用的加密模式为：{id}password 它会根据id判断加密模式
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    ```
  - 测试加密解密
    ```java
    @Test
    void testBcript() {
        String password1 = passwordEncoder.encode("admin");
        String password2 = passwordEncoder.encode("admin");
        System.out.println(password1);
        System.out.println(password2);

        boolean flag1 = passwordEncoder.matches("admin", password1);
        boolean flag2 = passwordEncoder.matches("admin", password2);
        System.out.println(flag1);
        System.out.println(flag2);
    }
    ```
    ```txt
    result：
      $2a$10$LT1Z6F5NLYzHn6Vm4AJwN.SXLP.nZzDscUbuG/sZ9aaxwBxhwlWia
      $2a$10$exw8ZKU9N0tg/rJZy9QfhezCeYab1wIdYTjKAprIOu4y.RxRdbef2
      true
      true
    ```

## 权限设置

### 代码初次改造
权限设置使用的是 `FilterSecurityInterceptor` 权限拦截器

- `@EnableGlobalMethodSecurity(prePostEnabled = true)` 基于注解的权限控制方案，配置之后就可以使用 `@PreAuthorize` 注解修饰相关方法了
- `SecurityContextHolder.getContext().setAuthentication` 时将权限设置进去
  - 1. public Collection<? extends GrantedAuthority> getAuthorities() 方法重写
    ```java
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
      if (authorities != null) {
        return authorities;
      }
      authorities = permissions.stream()
                .map(SimpleGrantedAuthority::new).collect(Collectors.toList());
      return authorities;
    }
    ```
  - 2. 认证过滤器中添加权限内容 
    ```java
    /* loginUser.getAuthorities() 为权限信息 */
    SecurityContextHolder.getContext().setAuthentication(
            UsernamePasswordAuthenticationToken.authenticated(
                    loginUser, null, loginUser.getAuthorities()));  
    ```    
- 自定义登录中添加权限内容
- 通过 `@PreAuthorize("hasAuthority('address')")` 设置接口权限

### 数据库添加用户角色及权限信息

```sql

-- ----------------------------
-- Table structure for sys_menu
-- ----------------------------
DROP TABLE IF EXISTS `sys_menu`;
CREATE TABLE `sys_menu`  (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `menu_name` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL DEFAULT 'NULL' COMMENT '菜单名',
  `path` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '路由地址',
  `component` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '组件路径',
  `visible` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '0' COMMENT '菜单状态（0显示 1隐藏）',
  `status` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '0' COMMENT '菜单状态（0正常 1停用）',
  `perms` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '权限标识',
  `icon` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '#' COMMENT '菜单图标',
  `create_by` bigint(20) DEFAULT NULL,
  `create_time` datetime(0) DEFAULT NULL,
  `update_by` bigint(20) DEFAULT NULL,
  `update_time` datetime(0) DEFAULT NULL,
  `del_flag` int(11) DEFAULT 0 COMMENT '是否删除（0未删除 1已删除）',
  `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '备注',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 2 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '菜单表' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for sys_role
-- ----------------------------
DROP TABLE IF EXISTS `sys_role`;
CREATE TABLE `sys_role`  (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL,
  `role_key` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '角色权限字符串',
  `status` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '0' COMMENT '角色状态（0正常 1停用）',
  `del_flag` int(1) DEFAULT 0 COMMENT 'del_flag',
  `create_by` bigint(200) DEFAULT NULL,
  `create_time` datetime(0) DEFAULT NULL,
  `update_by` bigint(200) DEFAULT NULL,
  `update_time` datetime(0) DEFAULT NULL,
  `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '备注',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 3 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '角色表' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for sys_role_menu
-- ----------------------------
DROP TABLE IF EXISTS `sys_role_menu`;
CREATE TABLE `sys_role_menu`  (
  `role_id` bigint(200) NOT NULL AUTO_INCREMENT COMMENT '角色ID',
  `menu_id` bigint(200) NOT NULL DEFAULT 0 COMMENT '菜单id',
  PRIMARY KEY (`role_id`, `menu_id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 2 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for sys_user
-- ----------------------------
DROP TABLE IF EXISTS `sys_user`;
CREATE TABLE `sys_user`  (
  `id` bigint(20) UNSIGNED ZEROFILL NOT NULL AUTO_INCREMENT COMMENT '主键',
  `user_name` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT 'NULL' COMMENT '用户名',
  `nick_name` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT 'NULL' COMMENT '昵称',
  `password` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT 'NULL' COMMENT '密码',
  `status` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT '0' COMMENT '账号状态（0正常 1停用）',
  `email` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL COMMENT '邮箱',
  `phonenumber` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL COMMENT '手机号',
  `sex` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL COMMENT '用户性别（0男，1女，2未知）',
  `avatar` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL COMMENT '头像',
  `user_type` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '1' COMMENT '用户类型（0管理员，1普通用户）',
  `create_by` bigint(20) DEFAULT NULL COMMENT '创建人的用户id',
  `create_time` datetime(0) NOT NULL COMMENT '创建时间',
  `update_by` bigint(20) DEFAULT NULL COMMENT '更新人',
  `update_time` datetime(0) DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  `del_flag` int(11) DEFAULT 0 COMMENT '删除标志（0代表未删除，1代表已删除）',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 4 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for sys_user_role
-- ----------------------------
DROP TABLE IF EXISTS `sys_user_role`;
CREATE TABLE `sys_user_role`  (
  `user_id` bigint(200) NOT NULL AUTO_INCREMENT COMMENT '用户id',
  `role_id` bigint(200) NOT NULL DEFAULT 0 COMMENT '角色id',
  PRIMARY KEY (`user_id`, `role_id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = Dynamic;
```


### 添加菜单权限实体以及 sql 请求

```java
/**
 * 菜单表实体类
 *
 * @author: melii ma
 * @date: 2022/9/20 21:06
 */
@TableName(value = "sys_menu")
@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Menu implements Serializable {

    private static final long serialVersionUID = 1L;

    @TableId
    private Long id;

    /**
     * 菜单名
     */
    private String menuName;

    /**
     * 路由地址
     */
    private String path;

    /**
     * 组件路径
     */
    private String component;

    /**
     * 菜单状态（0显示 1隐藏）
     */
    private String visible;

    /**
     * 菜单状态（0正常 1停用）
     */
    private String status;

    /**
     * 权限标识
     */
    private String perms;

    /**
     * 菜单图标
     */
    private String icon;

    private Long createBy;

    private Date createTime;

    private Long updateBy;

    private Date updateTime;

    /**
     * 是否删除（0未删除 1已删除）
     */
    private Integer delFlag;

    /**
     * 备注
     */
    private String remark;
}
```

```java
public interface MenuMapper extends BaseMapper<Menu> {

    List<String> selectPermsByUserId(@Param("userId") Long userId);

}

```

```properties
mybatis-plus.mapper-locations=classpath*:/mapper/**/*.xml
```

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd" >
<mapper namespace="com.ml.demo.security.dao.MenuMapper">

    <select id="selectPermsByUserId" parameterType="long" resultType="string">
        SELECT DISTINCT perms from sys_menu where id in (
            SELECT menu_id  from sys_role_menu where role_id in (
                SELECT role_id from sys_user_role where user_id = #{userId}
            )
        ) and status='0'
    </select>

</mapper>
```

## 关于 JWT

### JWT 简介

Json Web Token（JWT） 是一个轻巧的规范，它允许我们使用JWT在用户和服务区之间传递安全可靠的信息。

- 好处：不需要服务端存储session信息
- 特点：无状态，可以被看到，但是不能被篡改（第三部分的组成中使用了密钥）

**一个JWT实际上是三部分组成的，头部、载荷和签名**

```
eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI2NjYiLCJzdWIiOiJ0ZXN0Snd0IiwiaWF0IjoxNjYyOTYwNjE0fQ.yv7siArODVdnHmM9JxGtknQjgeODlH34nICFJBZxytk
```

#### 头部

头部用于描述该JWT最基本的信息，包括其类型以及签名所使用的算法等，他可以被表示为一个json
```
{"alg":"HS256"}

加密后

eyJhbGciOiJIUzI1NiJ9
```

#### 载荷

载荷就是存放有效信息的地方，也就是当前用户的有效信息

```
{"jti":"666","sub":"testJwt","iat":1662960614}

加密后

eyJqdGkiOiI2NjYiLCJzdWIiOiJ0ZXN0Snd0IiwiaWF0IjoxNjYyOTYwNjE0fQ
```

#### 签证

JWT的第三部分是一个签证，签证信息是由三部分组成的
> header（头部信息）  
> payload（载荷信息）  
> secret（密钥）

这一部分是通过base64加密后的header和payload信息使用.连接组成的字符串，并通过header中声明的加密方式进行加盐secret组合加密


## 什么是 `RBAC（Role-Based Access Control）`

> RBAC（Role-Based Access Control），基于角色的访问控制。通过用户关联角色，角色关联权限，来间接的为用户赋予权限。

## 全局异常处理

对于 security 的异常处理是在 ExceptionTranslationFilter 过滤器中的 handleSpringSecurityException 方法中进行判断

```java
// ExceptionTranslationFilter 的 doFilter 方法中若是发现存在异常会进行异常处理
private void handleSpringSecurityException(HttpServletRequest request, HttpServletResponse response,
			FilterChain chain, RuntimeException exception) throws IOException, ServletException {
    if (exception instanceof AuthenticationException) {
        handleAuthenticationException(request, response, chain, (AuthenticationException) exception);
    }
    else if (exception instanceof AccessDeniedException) {
        handleAccessDeniedException(request, response, chain, (AccessDeniedException) exception);
    }
}
```

- 认证失败：`AuthenticationException`, 后续会调用 `AuthenticationEntryPoint` 的 `commence` 方法
- 授权失败：`AccessDeniedException`，后续会调用 `AccessDeniedHandler` 的 `handle` 方法

我们可以通过自己实现接口来完成认证失败及授权失败的异常处理
```java

@Component
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        ResponseResult responseResult = new ResponseResult(HttpStatus.FORBIDDEN.value(), "您的权限不足");
        String json = JSON.toJSONString(responseResult);
        WebUtil.renderString(response, json);
    }
}


@Component
public class AuthenticationEntryPointImpl implements AuthenticationEntryPoint {

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
    ResponseResult responseResult = new ResponseResult(HttpStatus.UNAUTHORIZED.value(), "登录失败了，请重新登录");
    String json = JSON.toJSONString(responseResult);
    WebUtil.renderString(response, json);

  }
}


```

处理之外我们还需要在 security 的配置类中设置我们新建的实现类

```java
@Autowired
private AuthenticationEntryPointImpl authenticationEntryPoint;

@Autowired
private AccessDeniedHandlerImpl accessDeniedHandler;

@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    
    // ......
    
    // 设置 security 如何处理异常
    http.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint).accessDeniedHandler(accessDeniedHandler);
    return http.build();
}
```

在具体的项目开发中，我们还需要使用 `@ControllerAdvice` 进行全局的异常处理。以此达到一个json格式的返回值

```java
@ControllerAdvice
public class GlobalExceptionHandler {

    /* 
     * 对于异常内容的内容我们可以通过多次使用 @ExceptionHandler 来对异常进行更细化的处理
     * 
     * 并且后续可以自定义异常，在自定义的异常处理中写入自己需要的个性化内容
     */
  
    @ExceptionHandler(Exception.class)
    public ResponseResult failed(Exception e) {
        return new ResponseResult(HttpStatus.INTERNAL_SERVER_ERROR.value(), e);
    }

}

```