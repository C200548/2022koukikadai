package jp.ac.ccmc._2x.kimatsu2021;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

import lombok.Data;

@Data
@Entity
public class Account {
	@Id
	@GeneratedValue
	private Long id;

	private String name;
	private String className;
	private String tel;
	private String address;

	public Account() {
		super();
	}

	public Account(String name, String className, String tel, String address) {
		super();
		this.name = name;
        this.className = className;
		this.tel = tel;
		this.address = address;
	}
}