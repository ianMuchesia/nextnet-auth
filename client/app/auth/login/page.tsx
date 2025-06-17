'use client';
import axios from 'axios';
import React from 'react';
import { useRouter } from 'next/navigation';

const LoginPage = () => {
  const router = useRouter();

  const handleLogin = async(event: React.FormEvent) => {
    event.preventDefault();

    try {
      const email = (event.target as HTMLFormElement).email.value;
      const password = (event.target as HTMLFormElement).password.value;

      const res = await axios.post(`${process.env.NEXT_PUBLIC_API_URL}/auth/login`, {
        email,
        password,
      }, {
        // This is crucial for receiving cookies from the server
        withCredentials: true
      });

      // If login was successful, redirect to dashboard or home page
      if (res.data.message === "Login successful") {
        // Store user data if needed in localStorage or React state
        localStorage.setItem('user', JSON.stringify(res.data.user));
        
        // Redirect to home page or dashboard
        router.push('/');
      }
    } catch (error) {
      console.error('Login error:', error);
      // Handle login errors (display an error message)
      alert('Login failed. Please check your credentials.');
    }
  };

  return (
    <div className="flex items-center justify-center h-screen bg-gray-100">
      <div className="bg-white p-8 rounded-lg shadow-md w-96">
        <h2 className="text-2xl font-bold mb-6 text-center">Login</h2>
        <form onSubmit={handleLogin}>
          {/* Missing onSubmit handler in your original code */}
          <div className="mb-4">
            <label className="block text-sm font-medium mb-2" htmlFor="email">
              Email
            </label>
            <input
              type="email"
              id="email"
              className="w-full px-3 py-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
            />
          </div>
          <div className="mb-6">
            <label className="block text-sm font-medium mb-2" htmlFor="password">
              Password
            </label>
            <input
              type="password"
              id="password"
              className="w-full px-3 py-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
            />
          </div>
          <button
            type="submit"
            className="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700 transition duration-200"
          >
            Login
          </button>
        </form>
      </div>
    </div>
  );
};

export default LoginPage;