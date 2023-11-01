package com.example.demo3;

import android.annotation.SuppressLint;
import android.os.Bundle;
import android.util.Base64;
import android.view.View;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.example.demo3.databinding.ActivityMainBinding;


public class MainActivity extends AppCompatActivity {

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        binding.submit.setOnClickListener(new View.OnClickListener() {
            @SuppressLint("SetTextI18n")
            @Override
            public void onClick(View view) {
                String name = binding.name.getText().toString();
                String password = binding.password.getText().toString();
                binding.message.setText(
                        "Sending to server:\n" + Base64.encodeToString((name + ":" + password).getBytes(), Base64.DEFAULT)
                );
            }
        });
    }

    @SuppressLint("SetTextI18n")
    private void showTime() {
        binding.hide.setText("" + System.currentTimeMillis(), TextView.BufferType.EDITABLE);
    }
}