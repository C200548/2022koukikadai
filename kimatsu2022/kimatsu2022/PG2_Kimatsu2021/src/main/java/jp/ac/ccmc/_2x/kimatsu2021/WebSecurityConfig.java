package jp.ac.ccmc._2x.kimatsu2021;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
				.antMatchers("/", "/home").permitAll()
				.anyRequest().authenticated()
				.and()
			.formLogin()
				.loginPage("/login")
				.permitAll()
				.and()
			.logout()
				.permitAll();
	}


    @Override
    protected void configure(AuthenticationManagerBuilder auth)throws Exception{
        String password = passwordEncoder().encode("password");
        auth
            .inMemoryAuthentication()
                .passwordEncoder(passwordEncoder())
                .withUser("user").password(password).roles("user");
        

        String password2 = passwordEncoder().encode("ShiKi+2021");
        auth
            .inMemoryAuthentication()
                .passwordEncoder(passwordEncoder())
                .withUser("ccmc").password(password2).roles("USER");

    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
