import React from "react";

const Biography = ({imageUrl}) => {
  return (
    <>
      <div className="container biography">
        <div className="banner">
          <img src={imageUrl} alt="whoweare" />
        </div>
        <div className="banner">
          <h3>Who We Are</h3>
          <p>
          Zenith Medical Institute is a premier healthcare institution renowned for its commitment to excellence in patient care and medical innovation. Over the years, Zenith has successfully implemented numerous cutting-edge treatment programs and research initiatives, making significant contributions to various fields, including oncology, cardiology, and neurology. Their team of highly skilled professionals is dedicated to advancing medical knowledge and improving patient outcomes through evidence-based practices. Zenith's extensive experience in delivering comprehensive healthcare services reflects its mission to promote wellness and provide top-quality medical solutions tailored to the needs of the community.
          </p>
        </div>
      </div>
    </>
  );
};

export default Biography;
