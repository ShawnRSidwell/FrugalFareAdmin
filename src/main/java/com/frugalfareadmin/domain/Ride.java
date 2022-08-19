package com.frugalfareadmin.domain;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

@Entity
@Table(name = "ride")
public class Ride {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "id")
	private int id;

	@Column(name = "start_address")
	private String startAddress;

	@Column(name = "end_address")
	private String endAddress;

	@Column(name = "lat1")
	private Double lat1;

	@Column(name = "long1")
	private Double long1;

	@Column(name = "lat2")
	private Double lat2;

	@Column(name = "long2")
	private Double long2;

	@Column(name = "miles")
	private Double miles;

	@Column(name = "uber_price")
	private Double uberPrice;

	@Column(name = "lyft_price")
	private Double lyftPrice;

	@Column(name = "taxi_price")
	private Double taxiPrice;

	@ManyToOne
	@JoinColumn(name = "user_id")
	private User user;

	public Ride() {
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public String getStartAddress() {
		return startAddress;
	}

	public void setStartAddress(String startAddress) {
		this.startAddress = startAddress;
	}

	public String getEndAddress() {
		return endAddress;
	}

	public void setEndAddress(String endAddress) {
		this.endAddress = endAddress;
	}

	public Double getLat1() {
		return lat1;
	}

	public void setLat1(Double lat1) {
		this.lat1 = lat1;
	}

	public Double getLong1() {
		return long1;
	}

	public void setLong1(Double long1) {
		this.long1 = long1;
	}

	public Double getLat2() {
		return lat2;
	}

	public void setLat2(Double lat2) {
		this.lat2 = lat2;
	}

	public Double getLong2() {
		return long2;
	}

	public void setLong2(Double long2) {
		this.long2 = long2;
	}

	public Double getMiles() {
		return miles;
	}

	public void setMiles(Double miles) {
		this.miles = miles;
	}

	public Double getUberPrice() {
		return uberPrice;
	}

	public void setUberPrice(Double uberPrice) {
		this.uberPrice = uberPrice;
	}

	public Double getLyftPrice() {
		return lyftPrice;
	}

	public void setLyftPrice(Double lyftPrice) {
		this.lyftPrice = lyftPrice;
	}

	public Double getTaxiPrice() {
		return taxiPrice;
	}

	public void setTaxiPrice(Double taxiPrice) {
		this.taxiPrice = taxiPrice;
	}

	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}

}
