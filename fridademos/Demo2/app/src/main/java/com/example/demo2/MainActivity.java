package com.example.demo2;

import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;

import androidx.appcompat.app.AppCompatActivity;
import androidx.navigation.NavController;
import androidx.navigation.Navigation;
import androidx.navigation.ui.AppBarConfiguration;
import androidx.navigation.ui.NavigationUI;

import com.example.demo2.databinding.ActivityMainBinding;
import com.google.android.material.snackbar.Snackbar;
import com.google.gson.Gson;

import java.util.Arrays;

public class MainActivity extends AppCompatActivity {

    private AppBarConfiguration appBarConfiguration;
    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        setSupportActionBar(binding.toolbar);

        NavController navController = Navigation.findNavController(this, R.id.nav_host_fragment_content_main);
        appBarConfiguration = new AppBarConfiguration.Builder(navController.getGraph()).build();
        NavigationUI.setupActionBarWithNavController(this, navController, appBarConfiguration);

        binding.fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
            }
        });

        test();
    }

    private static class Bean {
        String a;
        int b;
        float c;
    }

    private void test() {
        Bean[] beans = new Bean[3];
        beans[0] = new Bean();
        beans[0].a = "a";
        beans[0].b = 1;
        beans[0].c = 1f;

        beans[1] = new Bean();
        beans[1].a = "b";
        beans[1].b = 2;
        beans[1].c = 2f;

        beans[2] = new Bean();
        beans[2].a = "c";
        beans[2].b = 2;
        beans[2].c = 3f;

        String s1 = Arrays.toString(beans);
        Log.e("array", s1);
        String s = new Gson().toJson(beans);
        Log.e("gons", s);
    }

    Father father = new Father();
    Son son = new Son();
    Father father2 = new Son();

    IBook book = new SimpleBook();

    int ֏(int x) {
        return x + 100;
    }

    @Override
    protected void onResume() {
        super.onResume();
        int r = ֏(1000);
        Log.e("test", r + "");
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    @Override
    public boolean onSupportNavigateUp() {
        NavController navController = Navigation.findNavController(this, R.id.nav_host_fragment_content_main);
        return NavigationUI.navigateUp(navController, appBarConfiguration)
                || super.onSupportNavigateUp();
    }
}